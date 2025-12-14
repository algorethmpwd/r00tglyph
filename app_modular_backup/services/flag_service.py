#!/usr/bin/env python3
"""
Flag Service
============

This service handles all flag-related operations including:
- Secure flag generation with cryptographic randomness
- Flag validation and verification
- Flag lifecycle management (creation, usage, expiration)
- Anti-bruteforce protection
- Analytics and monitoring
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, request

from app import cache, db
from app.models import Challenge, Flag, Submission, User

logger = logging.getLogger(__name__)


class FlagService:
    """
    Comprehensive flag management service with security features
    """

    def __init__(self):
        self.flag_format = "R00T{{{}}}"
        self.flag_length = 32  # Length of the random part
        self.max_attempts_per_minute = 10
        self.flag_expiry_hours = 24  # Flags expire after 24 hours

        # Initialize encryption for sensitive flag data
        self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption for flag storage"""
        secret_key = current_app.config.get("SECRET_KEY", "default-key-change-me")

        # Derive encryption key from secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"rootglyph-salt",
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        self.cipher = Fernet(key)

    def generate_flag(self, challenge_id: int, user_id: int) -> str:
        """
        Generate a cryptographically secure unique flag

        Args:
            challenge_id (int): ID of the challenge
            user_id (int): ID of the user

        Returns:
            str: Generated flag in format R00T{...}
        """
        try:
            # Create unique seed from challenge, user, and timestamp
            timestamp = int(time.time())

            # Generate base data for flag
            base_data = f"{challenge_id}:{user_id}:{timestamp}:{secrets.token_hex(16)}"

            # Create HMAC for integrity and uniqueness
            secret_key = current_app.config.get("SECRET_KEY", "default-key")
            hmac_digest = hmac.new(
                secret_key.encode(), base_data.encode(), hashlib.sha256
            ).hexdigest()

            # Take first 32 characters for the flag
            flag_content = hmac_digest[: self.flag_length]

            # Format as R00T{...}
            flag_value = self.flag_format.format(flag_content)

            logger.info(f"Generated flag for challenge {challenge_id}, user {user_id}")
            return flag_value

        except Exception as e:
            logger.error(f"Error generating flag: {str(e)}")
            raise

    def get_or_create_flag(self, challenge_id: int, user_id: int) -> str:
        """
        Get existing valid flag or create a new one

        Args:
            challenge_id (int): Challenge ID
            user_id (int): User ID

        Returns:
            str: Flag value
        """
        try:
            # Check for existing unused flag
            existing_flag = Flag.query.filter_by(
                challenge_id=challenge_id, user_id=user_id, is_used=False
            ).first()

            # Return existing flag if valid and not expired
            if existing_flag and not existing_flag.is_expired():
                return existing_flag.flag_value

            # Mark expired flags as used
            if existing_flag and existing_flag.is_expired():
                existing_flag.is_used = True
                db.session.commit()

            # Generate new flag
            flag_value = self.generate_flag(challenge_id, user_id)

            # Store in database
            new_flag = Flag(
                challenge_id=challenge_id,
                user_id=user_id,
                flag_value=flag_value,
                expires_at=datetime.now(timezone.utc)
                + timedelta(hours=self.flag_expiry_hours),
            )

            db.session.add(new_flag)
            db.session.commit()

            return flag_value

        except Exception as e:
            logger.error(f"Error getting/creating flag: {str(e)}")
            raise

    def validate_flag(
        self, challenge_id: int, user_id: int, submitted_flag: str
    ) -> Tuple[bool, str]:
        """
        Validate submitted flag with comprehensive security checks

        Args:
            challenge_id (int): Challenge ID
            user_id (int): User ID
            submitted_flag (str): Flag submitted by user

        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        try:
            # Rate limiting check
            if not self._check_rate_limit(user_id, challenge_id):
                return False, "Too many attempts. Please wait before trying again."

            # Basic format validation
            if not self._validate_flag_format(submitted_flag):
                return False, "Invalid flag format. Expected format: R00T{...}"

            # Find matching flag in database
            valid_flag = Flag.query.filter_by(
                challenge_id=challenge_id,
                user_id=user_id,
                flag_value=submitted_flag,
                is_used=False,
            ).first()

            if not valid_flag:
                # Check if flag exists but for different user/challenge
                wrong_context = Flag.query.filter_by(flag_value=submitted_flag).first()
                if wrong_context:
                    self._log_security_event(
                        user_id,
                        challenge_id,
                        "flag_reuse_attempt",
                        {
                            "submitted_flag": submitted_flag,
                            "actual_owner": wrong_context.user_id,
                            "actual_challenge": wrong_context.challenge_id,
                        },
                    )
                    return False, "Invalid flag for this challenge."

                return False, "Invalid flag. Please check your solution."

            # Check expiration
            if valid_flag.is_expired():
                valid_flag.is_used = True
                db.session.commit()
                return False, "Flag has expired. Please generate a new one."

            # Mark flag as used
            valid_flag.mark_used()

            logger.info(
                f"Valid flag submitted for challenge {challenge_id} by user {user_id}"
            )
            return True, "Flag is valid! Challenge completed."

        except Exception as e:
            logger.error(f"Error validating flag: {str(e)}")
            return False, "Error validating flag. Please try again."

    def _validate_flag_format(self, flag: str) -> bool:
        """Validate flag format"""
        if not flag:
            return False

        # Check basic format R00T{...}
        if not flag.startswith("R00T{") or not flag.endswith("}"):
            return False

        # Extract content
        content = flag[5:-1]

        # Check content length and format
        if len(content) != self.flag_length:
            return False

        # Check if content is hexadecimal
        try:
            int(content, 16)
            return True
        except ValueError:
            return False

    def _check_rate_limit(self, user_id: int, challenge_id: int) -> bool:
        """Check rate limiting for flag submissions"""
        cache_key = f"flag_attempts:{user_id}:{challenge_id}"

        # Get current attempts count
        attempts = cache.get(cache_key, 0)

        if attempts >= self.max_attempts_per_minute:
            return False

        # Increment attempts counter
        cache.set(cache_key, attempts + 1, timeout=60)
        return True

    def _log_security_event(
        self, user_id: int, challenge_id: int, event_type: str, details: Dict[str, Any]
    ):
        """Log security events for monitoring"""
        event_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "challenge_id": challenge_id,
            "event_type": event_type,
            "ip_address": request.remote_addr if request else "unknown",
            "user_agent": request.headers.get("User-Agent") if request else "unknown",
            "details": details,
        }

        # Log to application logger
        logger.warning(f"Security event: {event_type}", extra=event_data)

        # Store in cache for admin dashboard
        cache_key = f"security_events:{int(time.time() // 3600)}"  # Hour buckets
        events = cache.get(cache_key, [])
        events.append(event_data)
        cache.set(cache_key, events, timeout=86400)  # 24 hour retention

    def regenerate_flag(
        self, challenge_id: int, user_id: int, reason: str = "user_request"
    ) -> str:
        """
        Regenerate flag for user (invalidates old one)

        Args:
            challenge_id (int): Challenge ID
            user_id (int): User ID
            reason (str): Reason for regeneration

        Returns:
            str: New flag value
        """
        try:
            # Mark existing flags as used
            existing_flags = Flag.query.filter_by(
                challenge_id=challenge_id, user_id=user_id, is_used=False
            ).all()

            for flag in existing_flags:
                flag.is_used = True

            db.session.commit()

            # Generate new flag
            new_flag_value = self.get_or_create_flag(challenge_id, user_id)

            # Log regeneration
            self._log_security_event(
                user_id,
                challenge_id,
                "flag_regenerated",
                {"reason": reason, "old_flags_count": len(existing_flags)},
            )

            return new_flag_value

        except Exception as e:
            logger.error(f"Error regenerating flag: {str(e)}")
            raise

    def get_flag_statistics(
        self, user_id: int = None, challenge_id: int = None
    ) -> Dict[str, Any]:
        """
        Get flag usage statistics

        Args:
            user_id (int, optional): Filter by user ID
            challenge_id (int, optional): Filter by challenge ID

        Returns:
            Dict[str, Any]: Statistics data
        """
        try:
            query = Flag.query

            if user_id:
                query = query.filter_by(user_id=user_id)
            if challenge_id:
                query = query.filter_by(challenge_id=challenge_id)

            flags = query.all()

            stats = {
                "total_flags": len(flags),
                "used_flags": len([f for f in flags if f.is_used]),
                "expired_flags": len([f for f in flags if f.is_expired()]),
                "active_flags": len(
                    [f for f in flags if not f.is_used and not f.is_expired()]
                ),
                "generation_rate": self._calculate_generation_rate(flags),
                "usage_patterns": self._analyze_usage_patterns(flags),
            }

            return stats

        except Exception as e:
            logger.error(f"Error getting flag statistics: {str(e)}")
            return {}

    def _calculate_generation_rate(self, flags: List[Flag]) -> Dict[str, float]:
        """Calculate flag generation rates"""
        if not flags:
            return {"per_hour": 0.0, "per_day": 0.0}

        # Get time range
        now = datetime.now(timezone.utc)
        oldest = min(f.generated_at for f in flags)
        time_diff = (now - oldest).total_seconds()

        if time_diff == 0:
            return {"per_hour": 0.0, "per_day": 0.0}

        flags_count = len(flags)

        return {
            "per_hour": (flags_count / time_diff) * 3600,
            "per_day": (flags_count / time_diff) * 86400,
        }

    def _analyze_usage_patterns(self, flags: List[Flag]) -> Dict[str, Any]:
        """Analyze flag usage patterns"""
        if not flags:
            return {}

        used_flags = [f for f in flags if f.is_used and f.used_at]

        if not used_flags:
            return {"average_time_to_use": None, "usage_distribution": {}}

        # Calculate average time from generation to usage
        time_diffs = []
        for flag in used_flags:
            if flag.used_at:
                diff = (flag.used_at - flag.generated_at).total_seconds()
                time_diffs.append(diff)

        avg_time = sum(time_diffs) / len(time_diffs) if time_diffs else 0

        # Usage distribution by hour
        usage_hours = {}
        for flag in used_flags:
            if flag.used_at:
                hour = flag.used_at.hour
                usage_hours[hour] = usage_hours.get(hour, 0) + 1

        return {
            "average_time_to_use_seconds": avg_time,
            "average_time_to_use_minutes": avg_time / 60,
            "usage_by_hour": usage_hours,
            "fastest_usage_seconds": min(time_diffs) if time_diffs else None,
            "slowest_usage_seconds": max(time_diffs) if time_diffs else None,
        }

    def cleanup_expired_flags(self) -> int:
        """
        Clean up expired flags (marks them as used)

        Returns:
            int: Number of flags cleaned up
        """
        try:
            expired_flags = Flag.query.filter(
                Flag.is_used == False, Flag.expires_at < datetime.now(timezone.utc)
            ).all()

            count = 0
            for flag in expired_flags:
                flag.is_used = True
                count += 1

            if count > 0:
                db.session.commit()
                logger.info(f"Cleaned up {count} expired flags")

            return count

        except Exception as e:
            logger.error(f"Error cleaning up expired flags: {str(e)}")
            return 0

    def get_user_flags(
        self, user_id: int, include_used: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get all flags for a user

        Args:
            user_id (int): User ID
            include_used (bool): Whether to include used flags

        Returns:
            List[Dict[str, Any]]: List of flag data
        """
        try:
            query = Flag.query.filter_by(user_id=user_id)

            if not include_used:
                query = query.filter_by(is_used=False)

            flags = query.order_by(Flag.generated_at.desc()).all()

            flag_data = []
            for flag in flags:
                data = {
                    "challenge_id": flag.challenge_id,
                    "challenge_title": flag.challenge.title
                    if flag.challenge
                    else "Unknown",
                    "flag_value": flag.flag_value if not flag.is_used else "[USED]",
                    "generated_at": flag.generated_at.isoformat(),
                    "expires_at": flag.expires_at.isoformat()
                    if flag.expires_at
                    else None,
                    "is_used": flag.is_used,
                    "used_at": flag.used_at.isoformat() if flag.used_at else None,
                    "is_expired": flag.is_expired(),
                    "time_remaining": self._get_time_remaining(flag),
                }
                flag_data.append(data)

            return flag_data

        except Exception as e:
            logger.error(f"Error getting user flags: {str(e)}")
            return []

    def _get_time_remaining(self, flag: Flag) -> Optional[int]:
        """Get remaining time in seconds for a flag"""
        if not flag.expires_at or flag.is_used:
            return None

        remaining = (flag.expires_at - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))

    def verify_flag_integrity(
        self, challenge_id: int, user_id: int, flag_value: str
    ) -> bool:
        """
        Verify flag was generated by our system (additional security check)

        Args:
            challenge_id (int): Challenge ID
            user_id (int): User ID
            flag_value (str): Flag to verify

        Returns:
            bool: True if flag integrity is valid
        """
        try:
            # Extract flag content
            if not self._validate_flag_format(flag_value):
                return False

            content = flag_value[5:-1]  # Remove R00T{ and }

            # This is a simplified integrity check
            # In production, you might store additional metadata
            # to verify the flag was generated by your system

            # Check if flag exists in our database
            flag_record = Flag.query.filter_by(
                challenge_id=challenge_id, user_id=user_id, flag_value=flag_value
            ).first()

            return flag_record is not None

        except Exception as e:
            logger.error(f"Error verifying flag integrity: {str(e)}")
            return False

    def get_flag_analytics(self, time_range: str = "24h") -> Dict[str, Any]:
        """
        Get comprehensive flag analytics

        Args:
            time_range (str): Time range for analytics (1h, 24h, 7d, 30d)

        Returns:
            Dict[str, Any]: Analytics data
        """
        try:
            # Calculate time threshold
            now = datetime.now(timezone.utc)
            time_deltas = {
                "1h": timedelta(hours=1),
                "24h": timedelta(days=1),
                "7d": timedelta(days=7),
                "30d": timedelta(days=30),
            }

            threshold = now - time_deltas.get(time_range, timedelta(days=1))

            # Get flags in time range
            flags = Flag.query.filter(Flag.generated_at >= threshold).all()
            submissions = Submission.query.filter(
                Submission.submitted_at >= threshold
            ).all()

            analytics = {
                "time_range": time_range,
                "period_start": threshold.isoformat(),
                "period_end": now.isoformat(),
                "flags_generated": len(flags),
                "flags_used": len([f for f in flags if f.is_used]),
                "successful_submissions": len([s for s in submissions if s.is_correct]),
                "failed_submissions": len([s for s in submissions if not s.is_correct]),
                "usage_rate": len([f for f in flags if f.is_used]) / len(flags) * 100
                if flags
                else 0,
                "success_rate": len([s for s in submissions if s.is_correct])
                / len(submissions)
                * 100
                if submissions
                else 0,
                "top_challenges": self._get_top_challenges_by_activity(
                    flags, submissions
                ),
                "user_activity": self._get_user_activity_stats(flags, submissions),
            }

            return analytics

        except Exception as e:
            logger.error(f"Error getting flag analytics: {str(e)}")
            return {}

    def _get_top_challenges_by_activity(
        self, flags: List[Flag], submissions: List[Submission]
    ) -> List[Dict[str, Any]]:
        """Get most active challenges by flag generation and submissions"""
        challenge_activity = {}

        for flag in flags:
            cid = flag.challenge_id
            if cid not in challenge_activity:
                challenge_activity[cid] = {
                    "flags": 0,
                    "submissions": 0,
                    "challenge_title": "",
                }
            challenge_activity[cid]["flags"] += 1

            if flag.challenge:
                challenge_activity[cid]["challenge_title"] = flag.challenge.title

        for submission in submissions:
            cid = submission.challenge_id
            if cid not in challenge_activity:
                challenge_activity[cid] = {
                    "flags": 0,
                    "submissions": 0,
                    "challenge_title": "",
                }
            challenge_activity[cid]["submissions"] += 1

            if submission.challenge:
                challenge_activity[cid]["challenge_title"] = submission.challenge.title

        # Sort by total activity
        sorted_challenges = sorted(
            challenge_activity.items(),
            key=lambda x: x[1]["flags"] + x[1]["submissions"],
            reverse=True,
        )

        return [
            {
                "challenge_id": cid,
                "title": data["challenge_title"],
                "flags_generated": data["flags"],
                "submissions": data["submissions"],
                "total_activity": data["flags"] + data["submissions"],
            }
            for cid, data in sorted_challenges[:10]
        ]

    def _get_user_activity_stats(
        self, flags: List[Flag], submissions: List[Submission]
    ) -> Dict[str, Any]:
        """Get user activity statistics"""
        unique_flag_users = set(f.user_id for f in flags)
        unique_submission_users = set(s.user_id for s in submissions)

        return {
            "active_flag_users": len(unique_flag_users),
            "active_submission_users": len(unique_submission_users),
            "total_active_users": len(unique_flag_users | unique_submission_users),
            "average_flags_per_user": len(flags) / len(unique_flag_users)
            if unique_flag_users
            else 0,
            "average_submissions_per_user": len(submissions)
            / len(unique_submission_users)
            if unique_submission_users
            else 0,
        }
