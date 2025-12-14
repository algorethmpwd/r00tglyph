#!/usr/bin/env python3
"""
Base Challenge Controller
========================

This module provides the base controller class for all challenge categories.
It includes level-specific hints, solutions, flag generation, and progress tracking.
All challenge controllers inherit from this base class for consistency.
"""

import hashlib
import json
import os
import random
import string
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.services.analytics_service import AnalyticsService
from app.services.flag_service import FlagService
from app.services.progress_service import ProgressService
from flask import current_app, g, request, session
from werkzeug.exceptions import Forbidden, NotFound

from app import db
from app.models import Challenge, Flag, Hint, Submission, User, UserChallenge


class BaseChallenge(ABC):
    """
    Abstract base class for all challenge controllers

    Provides common functionality:
    - User authentication and authorization
    - Flag generation and validation
    - Progress tracking and scoring
    - Level-specific hints and solutions
    - Analytics and attempt logging
    """

    def __init__(self, category: str, level: int):
        """
        Initialize challenge controller

        Args:
            category (str): Challenge category (xss, sqli, etc.)
            level (int): Challenge level (1-23)
        """
        self.category = category
        self.level = level
        self.challenge = self._get_challenge()
        self.user = self._get_current_user()
        self.user_challenge = self._get_or_create_user_challenge()

        # Services
        self.flag_service = FlagService()
        self.progress_service = ProgressService()
        self.analytics_service = AnalyticsService()

        # Initialize level-specific data
        self.hints = self._load_level_hints()
        self.solution = self._load_level_solution()
        self.vulnerability_info = self._load_vulnerability_info()

    def _get_current_user(self) -> Optional[User]:
        """Get current authenticated user"""
        if "user_id" not in session:
            return None
        return User.query.get(session["user_id"])

    def _get_challenge(self) -> Challenge:
        """Get challenge from database"""
        challenge = Challenge.query.filter_by(
            category=self.category, level=self.level
        ).first()

        if not challenge:
            raise NotFound(f"Challenge {self.category}/level{self.level} not found")

        if not challenge.is_active:
            raise Forbidden("This challenge is currently disabled")

        return challenge

    def _get_or_create_user_challenge(self) -> UserChallenge:
        """Get or create user challenge tracking record"""
        if not self.user:
            raise Forbidden("Authentication required")

        user_challenge = UserChallenge.query.filter_by(
            user_id=self.user.id, challenge_id=self.challenge.id
        ).first()

        if not user_challenge:
            user_challenge = UserChallenge(
                user_id=self.user.id, challenge_id=self.challenge.id
            )
            db.session.add(user_challenge)
            db.session.commit()

        return user_challenge

    def _load_level_hints(self) -> List[Dict[str, Any]]:
        """Load level-specific hints from data files"""
        hints_file = os.path.join(
            current_app.root_path,
            "data",
            "hints",
            f"{self.category}_level{self.level}.json",
        )

        if os.path.exists(hints_file):
            with open(hints_file, "r", encoding="utf-8") as f:
                return json.load(f)

        # Return default hints if file doesn't exist
        return self._get_default_hints()

    def _load_level_solution(self) -> Dict[str, Any]:
        """Load level-specific solution from data files"""
        solution_file = os.path.join(
            current_app.root_path,
            "data",
            "solutions",
            f"{self.category}_level{self.level}.json",
        )

        if os.path.exists(solution_file):
            with open(solution_file, "r", encoding="utf-8") as f:
                return json.load(f)

        return self._get_default_solution()

    def _load_vulnerability_info(self) -> Dict[str, Any]:
        """Load vulnerability information for educational context"""
        info_file = os.path.join(
            current_app.root_path,
            "data",
            "challenges",
            f"{self.category}_vulnerabilities.json",
        )

        if os.path.exists(info_file):
            with open(info_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get(f"level{self.level}", {})

        return {}

    def _get_default_hints(self) -> List[Dict[str, Any]]:
        """Get default hints when no specific hints file exists"""
        return [
            {
                "order": 1,
                "title": "Getting Started",
                "content": f"This is a {self.category.upper()} challenge at level {self.level}. "
                "Look for ways to inject malicious input.",
                "type": "text",
                "difficulty": 1,
                "unlock_after_attempts": 0,
                "points_cost": 5,
            },
            {
                "order": 2,
                "title": "Common Techniques",
                "content": "Try different payloads and observe the application's behavior. "
                "Use browser developer tools to analyze responses.",
                "type": "text",
                "difficulty": 2,
                "unlock_after_attempts": 2,
                "points_cost": 10,
            },
            {
                "order": 3,
                "title": "Solution Approach",
                "content": "Consider using security testing tools like Burp Suite or manual techniques "
                "to identify and exploit the vulnerability.",
                "type": "text",
                "difficulty": 3,
                "unlock_after_attempts": 5,
                "points_cost": 20,
            },
        ]

    def _get_default_solution(self) -> Dict[str, Any]:
        """Get default solution when no specific solution file exists"""
        return {
            "summary": f"Generic solution for {self.category.upper()} Level {self.level}",
            "steps": [
                "1. Identify the input points in the application",
                "2. Test for vulnerability using appropriate payloads",
                "3. Exploit the vulnerability to achieve the objective",
                "4. Submit the flag to complete the challenge",
            ],
            "payloads": [],
            "tools_used": ["Browser Developer Tools"],
            "learning_points": [
                f"Understanding {self.category.upper()} vulnerabilities",
                "Manual testing techniques",
                "Security tool usage",
            ],
            "prevention": [
                "Input validation and sanitization",
                "Output encoding",
                "Security headers and policies",
            ],
        }

    def check_prerequisites(self) -> bool:
        """Check if user meets challenge prerequisites"""
        if not self.challenge.prerequisites:
            return True

        for prereq_id in self.challenge.prerequisites:
            completed = UserChallenge.query.filter_by(
                user_id=self.user.id, challenge_id=prereq_id, completed=True
            ).first()

            if not completed:
                return False

        return True

    def record_attempt(self, user_input: str = None, method: str = "web") -> None:
        """Record a challenge attempt for analytics"""
        self.user_challenge.record_attempt()

        # Log attempt for analytics
        self.analytics_service.log_attempt(
            user_id=self.user.id,
            challenge_id=self.challenge.id,
            user_input=user_input,
            method=method,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )

    def get_available_hints(self) -> List[Dict[str, Any]]:
        """Get hints available to user based on attempts and progress"""
        available_hints = []

        for hint in self.hints:
            # Check if hint is unlocked based on attempts
            if self.user_challenge.attempts_count >= hint.get(
                "unlock_after_attempts", 0
            ):
                # Check if user has enough points (if hint has cost)
                points_cost = hint.get("points_cost", 0)
                if points_cost == 0 or self.user.total_score >= points_cost:
                    available_hints.append(hint)

        return available_hints

    def use_hint(self, hint_order: int) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Use a hint and deduct points if necessary

        Returns:
            Tuple of (success, message, hint_data)
        """
        if not self.user_challenge.use_hint():
            return False, "No more hints available for this challenge", {}

        # Find the specific hint
        hint_data = None
        for hint in self.hints:
            if hint.get("order") == hint_order:
                hint_data = hint
                break

        if not hint_data:
            return False, "Hint not found", {}

        # Check if hint is available
        available_hints = self.get_available_hints()
        if hint_data not in available_hints:
            return False, "This hint is not yet available", {}

        # Deduct points if hint has cost
        points_cost = hint_data.get("points_cost", 0)
        if points_cost > 0:
            if self.user.total_score < points_cost:
                return (
                    False,
                    f"Insufficient points. Need {points_cost} points for this hint.",
                    {},
                )

            self.user.total_score -= points_cost
            db.session.commit()

        return True, f"Hint used! Points deducted: {points_cost}", hint_data

    def generate_flag(self) -> str:
        """Generate unique flag for this user and challenge"""
        return self.flag_service.generate_flag(self.challenge.id, self.user.id)

    def get_or_create_flag(self) -> str:
        """Get existing flag or create new one"""
        return self.flag_service.get_or_create_flag(self.challenge.id, self.user.id)

    def validate_flag(self, submitted_flag: str) -> Tuple[bool, str]:
        """
        Validate submitted flag

        Returns:
            Tuple of (is_valid, message)
        """
        return self.flag_service.validate_flag(
            self.challenge.id, self.user.id, submitted_flag.strip()
        )

    def submit_flag(self, submitted_flag: str, method: str = "web") -> Dict[str, Any]:
        """
        Process flag submission

        Returns:
            Dict with success status, message, and additional data
        """
        # Record the submission
        submission = Submission(
            user_id=self.user.id,
            challenge_id=self.challenge.id,
            submitted_flag=submitted_flag,
            submission_method=method,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )

        # Calculate time from start
        if self.user_challenge.first_attempt_at:
            time_diff = (
                datetime.now(timezone.utc) - self.user_challenge.first_attempt_at
            )
            submission.time_from_start = int(time_diff.total_seconds())

        # Validate flag
        is_valid, message = self.validate_flag(submitted_flag)
        submission.is_correct = is_valid

        db.session.add(submission)

        if is_valid:
            # Mark challenge as completed
            points_earned = self._calculate_points()
            bonus_points = self._calculate_bonus_points()

            self.user_challenge.mark_completed(
                points=points_earned, bonus=bonus_points, method=method
            )

            # Update progress and achievements
            self.progress_service.update_user_progress(self.user.id, self.challenge.id)

            # Log success analytics
            self.analytics_service.log_challenge_completion(
                user_id=self.user.id,
                challenge_id=self.challenge.id,
                completion_time=submission.time_from_start,
                attempts=self.user_challenge.attempts_count,
                hints_used=self.user_challenge.hints_used,
            )

            db.session.commit()

            return {
                "success": True,
                "message": "Congratulations! Challenge completed successfully!",
                "points_earned": points_earned,
                "bonus_points": bonus_points,
                "completion_time": submission.time_from_start,
                "flag": self.get_or_create_flag(),
            }
        else:
            db.session.commit()
            return {
                "success": False,
                "message": message,
                "attempts_remaining": self._get_attempts_remaining(),
            }

    def _calculate_points(self) -> int:
        """Calculate points earned for challenge completion"""
        base_points = self.challenge.base_points

        # Reduce points based on hints used
        hint_penalty = self.user_challenge.hints_used * 10

        # Minimum points threshold
        min_points = max(base_points // 4, 25)

        return max(base_points - hint_penalty, min_points)

    def _calculate_bonus_points(self) -> int:
        """Calculate bonus points for exceptional performance"""
        bonus = 0

        # Speed bonus (completed quickly)
        if self.user_challenge.attempts_count <= 3:
            bonus += 50

        # No hints bonus
        if self.user_challenge.hints_used == 0:
            bonus += 25

        # First attempt bonus
        if self.user_challenge.attempts_count == 1:
            bonus += 100

        return bonus

    def _get_attempts_remaining(self) -> Optional[int]:
        """Get remaining attempts for this challenge"""
        if self.challenge.max_attempts == 0:  # Unlimited
            return None

        return max(0, self.challenge.max_attempts - self.user_challenge.attempts_count)

    def get_challenge_context(self) -> Dict[str, Any]:
        """Get context data for template rendering"""
        return {
            "challenge": self.challenge,
            "user_challenge": self.user_challenge,
            "user": self.user,
            "level": self.level,
            "category": self.category,
            "category_display": self.get_category_display_name(),
            "available_hints": self.get_available_hints(),
            "vulnerability_info": self.vulnerability_info,
            "prerequisites_met": self.check_prerequisites(),
            "attempts_remaining": self._get_attempts_remaining(),
            "completion_percentage": self.user.get_completion_percentage(),
            "category_progress": self.user.get_category_progress(self.category),
        }

    def get_category_display_name(self) -> str:
        """Get human-readable category name"""
        display_names = {
            "xss": "Cross-Site Scripting (XSS)",
            "sqli": "SQL Injection (SQLi)",
            "cmdi": "Command Injection (CMDi)",
            "csrf": "Cross-Site Request Forgery (CSRF)",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "ssti": "Server-Side Template Injection (SSTI)",
            "deserial": "Insecure Deserialization",
            "auth": "Authentication Bypass",
            "xxe": "XML External Entity (XXE)",
        }
        return display_names.get(self.category, self.category.upper())

    def get_solution_data(self) -> Optional[Dict[str, Any]]:
        """Get solution data if challenge is completed"""
        if self.user_challenge.completed:
            return self.solution
        return None

    @abstractmethod
    def check_vulnerability(self, user_input: str, **kwargs) -> Tuple[bool, str]:
        """
        Check if user input contains vulnerability exploit

        This method must be implemented by each challenge controller
        to define specific vulnerability detection logic.

        Args:
            user_input (str): User input to check
            **kwargs: Additional parameters specific to challenge type

        Returns:
            Tuple of (vulnerability_detected, result_message)
        """
        pass

    @abstractmethod
    def get_challenge_template(self) -> str:
        """
        Get template name for this challenge

        Returns:
            Template path (e.g., 'xss/xss_level1.html')
        """
        pass

    def is_challenge_completed(self) -> bool:
        """Check if current user has completed this challenge"""
        return self.user_challenge.completed

    def get_next_challenge(self) -> Optional[Challenge]:
        """Get next challenge in sequence"""
        return Challenge.query.filter_by(
            category=self.category, level=self.level + 1, is_active=True
        ).first()

    def get_previous_challenge(self) -> Optional[Challenge]:
        """Get previous challenge in sequence"""
        if self.level <= 1:
            return None

        return Challenge.query.filter_by(
            category=self.category, level=self.level - 1, is_active=True
        ).first()

    def validate_time_limit(self) -> bool:
        """Check if challenge is within time limit"""
        if not self.challenge.time_limit:
            return True

        if not self.user_challenge.started_at:
            return True

        time_elapsed = datetime.now(timezone.utc) - self.user_challenge.started_at
        return time_elapsed.total_seconds() <= (self.challenge.time_limit * 60)

    def get_time_remaining(self) -> Optional[int]:
        """Get remaining time in seconds"""
        if not self.challenge.time_limit or not self.user_challenge.started_at:
            return None

        elapsed = datetime.now(timezone.utc) - self.user_challenge.started_at
        remaining = (self.challenge.time_limit * 60) - elapsed.total_seconds()

        return max(0, int(remaining))

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.category}-{self.level}>"
