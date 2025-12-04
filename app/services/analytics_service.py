#!/usr/bin/env python3
"""
Analytics Service
================

This service handles comprehensive analytics and tracking for R00tGlyph platform:
- User behavior analytics and learning patterns
- Challenge difficulty analysis and success metrics
- Security event monitoring and threat detection
- Performance metrics and system optimization insights
- Real-time dashboard data and reporting
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_

from app import cache, db
from app.models import (
    Challenge,
    DifficultyLevel,
    Flag,
    Submission,
    User,
    UserChallenge,
)

logger = logging.getLogger(__name__)


class AnalyticsService:
    """
    Comprehensive analytics service for platform insights and monitoring
    """

    def __init__(self):
        self.cache_timeout = 600  # 10 minutes default cache
        self.security_event_retention = 86400 * 7  # 7 days for security events

    def log_attempt(
        self,
        user_id: int,
        challenge_id: int,
        user_input: str = None,
        method: str = "web",
        ip_address: str = None,
        user_agent: str = None,
        success: bool = False,
    ) -> None:
        """
        Log challenge attempt for analytics

        Args:
            user_id (int): User ID
            challenge_id (int): Challenge ID
            user_input (str, optional): User input/payload
            method (str): Submission method (web, api, cli)
            ip_address (str, optional): Client IP
            user_agent (str, optional): User agent string
            success (bool): Whether attempt was successful
        """
        try:
            attempt_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "challenge_id": challenge_id,
                "method": method,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "input_length": len(user_input) if user_input else 0,
                "contains_xss_patterns": self._analyze_xss_patterns(user_input)
                if user_input
                else False,
                "contains_sqli_patterns": self._analyze_sqli_patterns(user_input)
                if user_input
                else False,
            }

            # Store in cache for real-time analytics
            cache_key = f"attempts:{datetime.now(timezone.utc).strftime('%Y%m%d%H')}"
            attempts = cache.get(cache_key, [])
            attempts.append(attempt_data)
            cache.set(cache_key, attempts, timeout=3600)

            # Log for persistent storage
            logger.info("Challenge attempt logged", extra=attempt_data)

        except Exception as e:
            logger.error(f"Error logging attempt: {str(e)}")

    def log_challenge_completion(
        self,
        user_id: int,
        challenge_id: int,
        completion_time: int,
        attempts: int,
        hints_used: int,
        method: str = "web",
    ) -> None:
        """
        Log challenge completion with performance metrics

        Args:
            user_id (int): User ID
            challenge_id (int): Challenge ID
            completion_time (int): Time taken in seconds
            attempts (int): Number of attempts made
            hints_used (int): Number of hints used
            method (str): Completion method
        """
        try:
            completion_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "challenge_id": challenge_id,
                "completion_time_seconds": completion_time,
                "completion_time_minutes": completion_time / 60
                if completion_time
                else 0,
                "attempts": attempts,
                "hints_used": hints_used,
                "method": method,
                "efficiency_score": self._calculate_completion_efficiency(
                    completion_time, attempts, hints_used
                ),
            }

            # Store completion event
            cache_key = f"completions:{datetime.now(timezone.utc).strftime('%Y%m%d')}"
            completions = cache.get(cache_key, [])
            completions.append(completion_data)
            cache.set(cache_key, completions, timeout=86400)

            # Update challenge difficulty metrics
            self._update_challenge_difficulty_metrics(
                challenge_id, completion_time, attempts
            )

            logger.info("Challenge completion logged", extra=completion_data)

        except Exception as e:
            logger.error(f"Error logging completion: {str(e)}")

    def get_user_analytics(self, user_id: int, days: int = 30) -> Dict[str, Any]:
        """
        Get comprehensive user analytics

        Args:
            user_id (int): User ID
            days (int): Analysis period in days

        Returns:
            Dict[str, Any]: User analytics data
        """
        try:
            cache_key = f"user_analytics:{user_id}:{days}"
            cached_analytics = cache.get(cache_key)
            if cached_analytics:
                return cached_analytics

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            # Basic user stats
            user = User.query.get(user_id)
            if not user:
                return {}

            # Challenge completion stats
            completions = UserChallenge.query.filter(
                UserChallenge.user_id == user_id,
                UserChallenge.completed == True,
                UserChallenge.completed_at >= cutoff_date,
            ).all()

            # Submission stats
            submissions = Submission.query.filter(
                Submission.user_id == user_id,
                Submission.submitted_at >= cutoff_date,
            ).all()

            # Calculate learning velocity
            learning_velocity = self._calculate_learning_velocity(completions, days)

            # Performance trends
            performance_trends = self._analyze_performance_trends(completions)

            # Category preferences
            category_preferences = self._analyze_category_preferences(completions)

            # Time-based patterns
            activity_patterns = self._analyze_activity_patterns(
                completions, submissions
            )

            # Difficulty progression
            difficulty_progression = self._analyze_difficulty_progression(completions)

            analytics_data = {
                "user_id": user_id,
                "analysis_period_days": days,
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
                "basic_stats": {
                    "challenges_completed": len(completions),
                    "total_submissions": len(submissions),
                    "success_rate": len([s for s in submissions if s.is_correct])
                    / len(submissions)
                    * 100
                    if submissions
                    else 0,
                    "avg_attempts_per_challenge": sum(
                        c.attempts_count for c in completions
                    )
                    / len(completions)
                    if completions
                    else 0,
                    "total_points_earned": sum(c.points_earned for c in completions),
                },
                "learning_velocity": learning_velocity,
                "performance_trends": performance_trends,
                "category_preferences": category_preferences,
                "activity_patterns": activity_patterns,
                "difficulty_progression": difficulty_progression,
                "recommendations": self._generate_user_recommendations(
                    user_id, completions
                ),
            }

            # Cache for 10 minutes
            cache.set(cache_key, analytics_data, timeout=self.cache_timeout)

            return analytics_data

        except Exception as e:
            logger.error(f"Error getting user analytics: {str(e)}")
            return {}

    def get_challenge_analytics(self, challenge_id: int) -> Dict[str, Any]:
        """
        Get comprehensive challenge analytics

        Args:
            challenge_id (int): Challenge ID

        Returns:
            Dict[str, Any]: Challenge analytics data
        """
        try:
            cache_key = f"challenge_analytics:{challenge_id}"
            cached_analytics = cache.get(cache_key)
            if cached_analytics:
                return cached_analytics

            challenge = Challenge.query.get(challenge_id)
            if not challenge:
                return {}

            # Get all attempts and completions
            user_challenges = UserChallenge.query.filter_by(
                challenge_id=challenge_id
            ).all()
            submissions = Submission.query.filter_by(challenge_id=challenge_id).all()

            # Calculate success metrics
            total_attempts = len(user_challenges)
            successful_completions = len([uc for uc in user_challenges if uc.completed])
            success_rate = (
                (successful_completions / total_attempts * 100)
                if total_attempts > 0
                else 0
            )

            # Time analysis
            completion_times = [
                uc.get_completion_time()
                for uc in user_challenges
                if uc.completed and uc.get_completion_time()
            ]
            avg_completion_time = (
                sum(completion_times) / len(completion_times) if completion_times else 0
            )

            # Attempt analysis
            attempt_counts = [
                uc.attempts_count for uc in user_challenges if uc.completed
            ]
            avg_attempts = (
                sum(attempt_counts) / len(attempt_counts) if attempt_counts else 0
            )

            # Hint usage analysis
            hint_usage = [uc.hints_used for uc in user_challenges]
            avg_hints = sum(hint_usage) / len(hint_usage) if hint_usage else 0

            # Difficulty assessment
            difficulty_score = self._calculate_challenge_difficulty_score(
                success_rate, avg_completion_time, avg_attempts
            )

            # Popular payload analysis
            payload_analysis = self._analyze_popular_payloads(challenge_id)

            # Time-based completion patterns
            completion_patterns = self._analyze_completion_patterns(user_challenges)

            analytics_data = {
                "challenge_id": challenge_id,
                "challenge_title": challenge.title,
                "category": challenge.category.value,
                "level": challenge.level,
                "difficulty": challenge.difficulty.value,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "engagement_metrics": {
                    "total_attempts": total_attempts,
                    "successful_completions": successful_completions,
                    "success_rate": round(success_rate, 2),
                    "abandonment_rate": round(100 - success_rate, 2),
                },
                "performance_metrics": {
                    "avg_completion_time_minutes": round(avg_completion_time, 2)
                    if avg_completion_time
                    else 0,
                    "avg_attempts_to_complete": round(avg_attempts, 2),
                    "avg_hints_used": round(avg_hints, 2),
                    "median_completion_time": self._calculate_median(completion_times)
                    if completion_times
                    else 0,
                },
                "difficulty_assessment": {
                    "calculated_difficulty_score": difficulty_score,
                    "difficulty_rating": self._get_difficulty_rating(difficulty_score),
                    "compared_to_category_avg": self._compare_to_category_average(
                        challenge
                    ),
                },
                "payload_analysis": payload_analysis,
                "completion_patterns": completion_patterns,
                "recommendations": self._generate_challenge_recommendations(
                    challenge, analytics_data
                ),
            }

            # Cache for 30 minutes
            cache.set(cache_key, analytics_data, timeout=1800)

            return analytics_data

        except Exception as e:
            logger.error(f"Error getting challenge analytics: {str(e)}")
            return {}

    def get_platform_analytics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get comprehensive platform-wide analytics

        Args:
            days (int): Analysis period in days

        Returns:
            Dict[str, Any]: Platform analytics data
        """
        try:
            cache_key = f"platform_analytics:{days}"
            cached_analytics = cache.get(cache_key)
            if cached_analytics:
                return cached_analytics

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            # User engagement metrics
            total_users = User.query.filter_by(is_active=True).count()
            active_users = User.query.filter(User.last_active >= cutoff_date).count()
            new_users = User.query.filter(User.created_at >= cutoff_date).count()

            # Challenge metrics
            total_challenges = Challenge.query.filter_by(is_active=True).count()
            completed_challenges = UserChallenge.query.filter(
                UserChallenge.completed == True,
                UserChallenge.completed_at >= cutoff_date,
            ).count()

            # Submission metrics
            total_submissions = Submission.query.filter(
                Submission.submitted_at >= cutoff_date
            ).count()
            successful_submissions = Submission.query.filter(
                Submission.submitted_at >= cutoff_date,
                Submission.is_correct == True,
            ).count()

            # Category popularity
            category_stats = self._get_category_popularity_stats(cutoff_date)

            # Learning path effectiveness
            learning_path_stats = self._get_learning_path_stats()

            # Security events
            security_events = self._get_security_event_summary(days)

            # Performance benchmarks
            performance_benchmarks = self._calculate_platform_performance_benchmarks()

            # Growth metrics
            growth_metrics = self._calculate_growth_metrics(days)

            analytics_data = {
                "analysis_period_days": days,
                "period_start": cutoff_date.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
                "user_engagement": {
                    "total_registered_users": total_users,
                    "active_users": active_users,
                    "new_users_period": new_users,
                    "engagement_rate": (active_users / total_users * 100)
                    if total_users > 0
                    else 0,
                    "avg_session_duration": self._calculate_avg_session_duration(days),
                },
                "challenge_metrics": {
                    "total_active_challenges": total_challenges,
                    "completions_period": completed_challenges,
                    "total_submissions": total_submissions,
                    "successful_submissions": successful_submissions,
                    "platform_success_rate": (
                        successful_submissions / total_submissions * 100
                    )
                    if total_submissions > 0
                    else 0,
                },
                "category_stats": category_stats,
                "learning_path_stats": learning_path_stats,
                "security_events": security_events,
                "performance_benchmarks": performance_benchmarks,
                "growth_metrics": growth_metrics,
                "system_health": self._get_system_health_metrics(),
            }

            # Cache for 15 minutes
            cache.set(cache_key, analytics_data, timeout=900)

            return analytics_data

        except Exception as e:
            logger.error(f"Error getting platform analytics: {str(e)}")
            return {}

    def _analyze_xss_patterns(self, user_input: str) -> bool:
        """Analyze if input contains XSS attack patterns"""
        if not user_input:
            return False

        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
            r"document\.",
            r"window\.",
            r"<iframe",
            r"<svg",
            r"<img.*onerror",
        ]

        import re

        for pattern in xss_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True

        return False

    def _analyze_sqli_patterns(self, user_input: str) -> bool:
        """Analyze if input contains SQL injection patterns"""
        if not user_input:
            return False

        sqli_patterns = [
            r"'\s*or\s*'",
            r"'\s*and\s*'",
            r"union\s+select",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from",
            r"update\s+.*\s+set",
            r"--",
            r"/\*.*\*/",
            r"'\s*;\s*--",
        ]

        import re

        for pattern in sqli_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True

        return False

    def _calculate_completion_efficiency(
        self, completion_time: int, attempts: int, hints_used: int
    ) -> float:
        """Calculate efficiency score for challenge completion"""
        try:
            # Base score
            score = 100.0

            # Time penalty (assuming 15 minutes is ideal)
            if completion_time and completion_time > 900:  # 15 minutes
                time_penalty = min(
                    50, (completion_time - 900) / 60
                )  # 1 point per minute over
                score -= time_penalty

            # Attempts penalty
            if attempts > 1:
                attempts_penalty = min(
                    30, (attempts - 1) * 5
                )  # 5 points per additional attempt
                score -= attempts_penalty

            # Hints penalty
            hints_penalty = hints_used * 10  # 10 points per hint
            score -= hints_penalty

            return max(0.0, round(score, 2))

        except Exception as e:
            logger.error(f"Error calculating completion efficiency: {str(e)}")
            return 0.0

    def _update_challenge_difficulty_metrics(
        self, challenge_id: int, completion_time: int, attempts: int
    ) -> None:
        """Update challenge difficulty metrics based on completion data"""
        try:
            # This would update challenge difficulty scoring
            # Implementation would depend on specific requirements
            pass

        except Exception as e:
            logger.error(f"Error updating challenge difficulty metrics: {str(e)}")

    def _calculate_learning_velocity(
        self, completions: List[UserChallenge], days: int
    ) -> Dict[str, Any]:
        """Calculate user's learning velocity metrics"""
        try:
            if not completions:
                return {"challenges_per_day": 0, "trend": "stable", "acceleration": 0}

            # Sort by completion date
            sorted_completions = sorted(completions, key=lambda c: c.completed_at)

            # Calculate challenges per day
            challenges_per_day = len(completions) / days if days > 0 else 0

            # Calculate trend (comparing first and second half of period)
            mid_point = len(sorted_completions) // 2
            if mid_point > 0:
                first_half = sorted_completions[:mid_point]
                second_half = sorted_completions[mid_point:]

                first_half_rate = len(first_half) / (days / 2)
                second_half_rate = len(second_half) / (days / 2)

                if second_half_rate > first_half_rate * 1.1:
                    trend = "accelerating"
                elif second_half_rate < first_half_rate * 0.9:
                    trend = "decelerating"
                else:
                    trend = "stable"

                acceleration = second_half_rate - first_half_rate
            else:
                trend = "stable"
                acceleration = 0

            return {
                "challenges_per_day": round(challenges_per_day, 2),
                "trend": trend,
                "acceleration": round(acceleration, 2),
                "total_in_period": len(completions),
            }

        except Exception as e:
            logger.error(f"Error calculating learning velocity: {str(e)}")
            return {}

    def _analyze_performance_trends(
        self, completions: List[UserChallenge]
    ) -> Dict[str, Any]:
        """Analyze user performance trends over time"""
        try:
            if not completions:
                return {}

            # Sort by completion date
            sorted_completions = sorted(completions, key=lambda c: c.completed_at)

            # Calculate rolling averages
            window_size = min(5, len(sorted_completions))

            performance_data = []
            for i in range(len(sorted_completions) - window_size + 1):
                window = sorted_completions[i : i + window_size]
                avg_attempts = sum(c.attempts_count for c in window) / len(window)
                avg_hints = sum(c.hints_used for c in window) / len(window)
                avg_time = sum(c.time_spent for c in window if c.time_spent) / len(
                    window
                )

                performance_data.append(
                    {
                        "completion_index": i + window_size,
                        "avg_attempts": avg_attempts,
                        "avg_hints": avg_hints,
                        "avg_time_minutes": avg_time / 60 if avg_time else 0,
                    }
                )

            # Calculate overall trend
            if len(performance_data) > 1:
                first_performance = performance_data[0]
                last_performance = performance_data[-1]

                attempts_trend = (
                    "improving"
                    if last_performance["avg_attempts"]
                    < first_performance["avg_attempts"]
                    else "declining"
                )
                hints_trend = (
                    "improving"
                    if last_performance["avg_hints"] < first_performance["avg_hints"]
                    else "declining"
                )
            else:
                attempts_trend = hints_trend = "stable"

            return {
                "performance_timeline": performance_data,
                "attempts_trend": attempts_trend,
                "hints_trend": hints_trend,
                "sample_size": len(sorted_completions),
            }

        except Exception as e:
            logger.error(f"Error analyzing performance trends: {str(e)}")
            return {}

    def _analyze_category_preferences(
        self, completions: List[UserChallenge]
    ) -> Dict[str, Any]:
        """Analyze user's category preferences and strengths"""
        try:
            if not completions:
                return {}

            category_stats = {}

            for completion in completions:
                challenge = completion.challenge
                category = challenge.category.value

                if category not in category_stats:
                    category_stats[category] = {
                        "count": 0,
                        "avg_attempts": 0,
                        "avg_hints": 0,
                        "avg_time": 0,
                        "total_points": 0,
                    }

                stats = category_stats[category]
                stats["count"] += 1
                stats["avg_attempts"] += completion.attempts_count
                stats["avg_hints"] += completion.hints_used
                stats["avg_time"] += (
                    completion.time_spent if completion.time_spent else 0
                )
                stats["total_points"] += completion.points_earned

            # Calculate averages
            for category, stats in category_stats.items():
                count = stats["count"]
                stats["avg_attempts"] = round(stats["avg_attempts"] / count, 2)
                stats["avg_hints"] = round(stats["avg_hints"] / count, 2)
                stats["avg_time"] = round(
                    stats["avg_time"] / count / 60, 2
                )  # Convert to minutes

            # Identify strongest and weakest categories
            if category_stats:
                strongest_category = min(
                    category_stats.keys(),
                    key=lambda k: category_stats[k]["avg_attempts"]
                    + category_stats[k]["avg_hints"],
                )
                weakest_category = max(
                    category_stats.keys(),
                    key=lambda k: category_stats[k]["avg_attempts"]
                    + category_stats[k]["avg_hints"],
                )
            else:
                strongest_category = weakest_category = None

            return {
                "category_breakdown": category_stats,
                "strongest_category": strongest_category,
                "weakest_category": weakest_category,
                "most_practiced": max(
                    category_stats.keys(), key=lambda k: category_stats[k]["count"]
                )
                if category_stats
                else None,
            }

        except Exception as e:
            logger.error(f"Error analyzing category preferences: {str(e)}")
            return {}

    def _analyze_activity_patterns(
        self, completions: List[UserChallenge], submissions: List[Submission]
    ) -> Dict[str, Any]:
        """Analyze user activity patterns by time"""
        try:
            if not completions and not submissions:
                return {}

            # Analyze by hour of day
            hourly_activity = {}
            for completion in completions:
                hour = completion.completed_at.hour
                hourly_activity[hour] = hourly_activity.get(hour, 0) + 1

            # Analyze by day of week
            daily_activity = {}
            for completion in completions:
                day = completion.completed_at.strftime("%A")
                daily_activity[day] = daily_activity.get(day, 0) + 1

            # Find peak activity times
            peak_hour = (
                max(hourly_activity.keys(), key=lambda k: hourly_activity[k])
                if hourly_activity
                else None
            )
            peak_day = (
                max(daily_activity.keys(), key=lambda k: daily_activity[k])
                if daily_activity
                else None
            )

            return {
                "hourly_distribution": hourly_activity,
                "daily_distribution": daily_activity,
                "peak_hour": peak_hour,
                "peak_day": peak_day,
                "total_active_hours": len(
                    [h for h, count in hourly_activity.items() if count > 0]
                ),
                "total_active_days": len(
                    [d for d, count in daily_activity.items() if count > 0]
                ),
            }

        except Exception as e:
            logger.error(f"Error analyzing activity patterns: {str(e)}")
            return {}

    def _analyze_difficulty_progression(
        self, completions: List[UserChallenge]
    ) -> Dict[str, Any]:
        """Analyze how user progresses through difficulty levels"""
        try:
            if not completions:
                return {}

            # Sort by completion date
            sorted_completions = sorted(completions, key=lambda c: c.completed_at)

            difficulty_sequence = []
            for completion in sorted_completions:
                challenge = completion.challenge
                difficulty_sequence.append(
                    {
                        "difficulty": challenge.difficulty.value,
                        "level": challenge.level,
                        "category": challenge.category.value,
                        "attempts": completion.attempts_count,
                        "completion_date": completion.completed_at.isoformat(),
                    }
                )

            # Analyze progression patterns
            difficulty_counts = {}
            for item in difficulty_sequence:
                diff = item["difficulty"]
                difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1

            # Check for proper progression
            has_proper_progression = True
            if len(difficulty_sequence) > 1:
                difficulty_order = ["beginner", "intermediate", "advanced", "expert"]
                prev_max_index = -1

                for item in difficulty_sequence:
                    current_index = difficulty_order.index(item["difficulty"])
                    if current_index > prev_max_index + 1:
                        has_proper_progression = False
                        break
                    prev_max_index = max(prev_max_index, current_index)

            return {
                "difficulty_sequence": difficulty_sequence,
                "difficulty_distribution": difficulty_counts,
                "has_proper_progression": has_proper_progression,
                "current_level": difficulty_sequence[-1]["difficulty"]
                if difficulty_sequence
                else "none",
                "ready_for_next_level": self._assess_readiness_for_next_level(
                    difficulty_sequence
                ),
            }

        except Exception as e:
            logger.error(f"Error analyzing difficulty progression: {str(e)}")
            return {}

    def _assess_readiness_for_next_level(self, difficulty_sequence: List[Dict]) -> bool:
        """Assess if user is ready for next difficulty level"""
        try:
            if not difficulty_sequence:
                return False

            # Get recent completions (last 5)
            recent_completions = difficulty_sequence[-5:]

            # Check average attempts for current difficulty
            current_difficulty = difficulty_sequence[-1]["difficulty"]
            current_level_completions = [
                c for c in recent_completions if c["difficulty"] == current_difficulty
            ]

            if len(current_level_completions) >= 3:
                avg_attempts = sum(
                    c["attempts"] for c in current_level_completions
                ) / len(current_level_completions)
                # Ready if averaging 2 or fewer attempts
                return avg_attempts <= 2.0

            return False

        except Exception as e:
            logger.error(f"Error assessing readiness for next level: {str(e)}")
            return False

    def _generate_user_recommendations(
        self, user_id: int, completions: List[UserChallenge]
    ) -> List[Dict[str, Any]]:
        """Generate personalized recommendations for user"""
        try:
            recommendations = []

            if not completions:
                recommendations.append(
                    {
                        "type": "getting_started",
                        "title": "Start Your Learning Journey",
                        "description": "Begin with beginner-level XSS challenges to build foundational skills.",
                        "priority": "high",
                    }
                )
                return recommendations

            # Analyze recent performance
            recent_completions = sorted(completions, key=lambda c: c.completed_at)[-10:]

            # Check for struggling areas
            struggling_categories = []
            for completion in recent_completions:
                if completion.attempts_count > 5 or completion.hints_used > 2:
                    category = completion.challenge.category.value
                    if category not in struggling_categories:
                        struggling_categories.append(category)

            if struggling_categories:
                recommendations.append(
                    {
                        "type": "skill_reinforcement",
                        "title": f"Strengthen {struggling_categories[0].upper()} Skills",
                        "description": f"Consider reviewing fundamentals or trying easier {struggling_categories[0]} challenges.",
                        "priority": "medium",
                        "categories": struggling_categories,
                    }
                )

            # Check for learning path suggestions
            if len(completions) >= 5:
                recommendations.append(
                    {
                        "type": "learning_path",
                        "title": "Join a Structured Learning Path",
                        "description": "Follow a guided curriculum to systematically build your skills.",
                        "priority": "low",
                    }
                )

            return recommendations

        except Exception as e:
            logger.error(f"Error generating user recommendations: {str(e)}")
            return []

    def _calculate_median(self, values: List[float]) -> float:
        """Calculate median of a list of values"""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        n = len(sorted_values)

        if n % 2 == 0:
            return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
        else:
            return sorted_values[n // 2]

    def _calculate_challenge_difficulty_score(
        self, success_rate: float, avg_completion_time: float, avg_attempts: float
    ) -> float:
        """Calculate difficulty score for a challenge"""
        try:
            # Base difficulty from success rate (lower success = higher difficulty)
            success_difficulty = (100 - success_rate) * 0.5

            # Time difficulty (longer time = higher difficulty)
            time_difficulty = min(avg_completion_time / 30, 50)  # Cap at 50 points

            # Attempts difficulty (more attempts = higher difficulty)
            attempts_difficulty = min((avg_attempts - 1) * 10, 30)  # Cap at 30 points

            total_difficulty = (
                success_difficulty + time_difficulty + attempts_difficulty
            )
            return min(100.0, max(0.0, round(total_difficulty, 2)))

        except Exception as e:
            logger.error(f"Error calculating challenge difficulty score: {str(e)}")
            return 50.0  # Default medium difficulty

    def _get_difficulty_rating(self, difficulty_score: float) -> str:
        """Convert difficulty score to rating"""
        if difficulty_score >= 80:
            return "Very Hard"
        elif difficulty_score >= 60:
            return "Hard"
        elif difficulty_score >= 40:
            return "Medium"
        elif difficulty_score >= 20:
            return "Easy"
        else:
            return "Very Easy"

    def _compare_to_category_average(self, challenge: Challenge) -> str:
        """Compare challenge difficulty to category average"""
        try:
            # Get other challenges in same category
            category_challenges = Challenge.query.filter_by(
                category=challenge.category, is_active=True
            ).all()

            if len(category_challenges) <= 1:
                return "No comparison data available"

            # Calculate average success rate for category
            success_rates = []
            for c in category_challenges:
                if c.id != challenge.id:
                    rate = (
                        c.get_success_rate() if hasattr(c, "get_success_rate") else 50
                    )
                    success_rates.append(rate)

            if not success_rates:
                return "No comparison data available"

            category_avg = sum(success_rates) / len(success_rates)
            challenge_rate = (
                challenge.get_success_rate()
                if hasattr(challenge, "get_success_rate")
                else 50
            )

            if challenge_rate < category_avg - 10:
                return "Harder than category average"
            elif challenge_rate > category_avg + 10:
                return "Easier than category average"
            else:
                return "Similar to category average"

        except Exception as e:
            logger.error(f"Error comparing to category average: {str(e)}")
            return "Comparison unavailable"

    def _analyze_popular_payloads(self, challenge_id: int) -> Dict[str, Any]:
        """Analyze popular payloads for a challenge"""
        try:
            # Get successful submissions for this challenge
            successful_submissions = Submission.query.filter_by(
                challenge_id=challenge_id, is_correct=True
            ).all()

            if not successful_submissions:
                return {"payload_patterns": [], "total_analyzed": 0}

            # Analyze payload patterns
            payload_counts = {}
            xss_patterns = []
            sqli_patterns = []

            for submission in successful_submissions:
                payload = submission.submitted_flag

                # Count exact payloads
                payload_counts[payload] = payload_counts.get(payload, 0) + 1

                # Analyze for common attack patterns
                if self._analyze_xss_patterns(payload):
                    xss_patterns.append(payload)
                if self._analyze_sqli_patterns(payload):
                    sqli_patterns.append(payload)

            # Get top payloads
            top_payloads = sorted(
                payload_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]

            return {
                "total_analyzed": len(successful_submissions),
                "unique_payloads": len(payload_counts),
                "top_payloads": [{"payload": p, "count": c} for p, c in top_payloads],
                "xss_pattern_count": len(xss_patterns),
                "sqli_pattern_count": len(sqli_patterns),
            }

        except Exception as e:
            logger.error(f"Error analyzing popular payloads: {str(e)}")
            return {}

    def _analyze_completion_patterns(
        self, user_challenges: List[UserChallenge]
    ) -> Dict[str, Any]:
        """Analyze completion patterns over time"""
        try:
            if not user_challenges:
                return {}

            completed_challenges = [uc for uc in user_challenges if uc.completed]

            if not completed_challenges:
                return {"completions_by_day": {}, "peak_completion_day": None}

            # Group by day
            completions_by_day = {}
            for uc in completed_challenges:
                day = uc.completed_at.strftime("%Y-%m-%d")
                completions_by_day[day] = completions_by_day.get(day, 0) + 1

            # Find peak day
            peak_day = (
                max(completions_by_day.keys(), key=lambda k: completions_by_day[k])
                if completions_by_day
                else None
            )

            return {
                "completions_by_day": completions_by_day,
                "peak_completion_day": peak_day,
                "total_completion_days": len(completions_by_day),
                "avg_completions_per_day": sum(completions_by_day.values())
                / len(completions_by_day)
                if completions_by_day
                else 0,
            }

        except Exception as e:
            logger.error(f"Error analyzing completion patterns: {str(e)}")
            return {}

    def _generate_challenge_recommendations(
        self, challenge: Challenge, analytics_data: Dict
    ) -> List[str]:
        """Generate recommendations for challenge improvement"""
        recommendations = []

        try:
            success_rate = analytics_data.get("engagement_metrics", {}).get(
                "success_rate", 0
            )
            avg_attempts = analytics_data.get("performance_metrics", {}).get(
                "avg_attempts_to_complete", 0
            )

            if success_rate < 30:
                recommendations.append(
                    "Consider adding more detailed hints or reducing difficulty"
                )
            elif success_rate > 90:
                recommendations.append(
                    "Challenge may be too easy - consider increasing complexity"
                )

            if avg_attempts > 10:
                recommendations.append(
                    "High attempt count suggests unclear instructions or excessive difficulty"
                )

            if (
                analytics_data.get("engagement_metrics", {}).get("abandonment_rate", 0)
                > 70
            ):
                recommendations.append(
                    "High abandonment rate - review challenge clarity and progression"
                )

            return recommendations

        except Exception as e:
            logger.error(f"Error generating challenge recommendations: {str(e)}")
            return []

    def _get_category_popularity_stats(self, cutoff_date: datetime) -> Dict[str, Any]:
        """Get category popularity statistics"""
        try:
            # Get completions by category
            category_completions = (
                db.session.query(
                    Challenge.category,
                    func.count(UserChallenge.id).label("completion_count"),
                )
                .join(UserChallenge)
                .filter(
                    UserChallenge.completed == True,
                    UserChallenge.completed_at >= cutoff_date,
                )
                .group_by(Challenge.category)
                .all()
            )

            category_stats = {}
            for category, count in category_completions:
                category_stats[category.value] = {
                    "completions": count,
                    "popularity_rank": 0,  # Will be set after sorting
                }

            # Rank by popularity
            sorted_categories = sorted(
                category_stats.items(), key=lambda x: x[1]["completions"], reverse=True
            )

            for rank, (category, stats) in enumerate(sorted_categories, 1):
                category_stats[category]["popularity_rank"] = rank

            return category_stats

        except Exception as e:
            logger.error(f"Error getting category popularity stats: {str(e)}")
            return {}

    def _get_learning_path_stats(self) -> Dict[str, Any]:
        """Get learning path effectiveness statistics"""
        try:
            # This would integrate with learning path system
            # Placeholder implementation
            return {
                "active_learning_paths": 0,
                "completion_rate": 0.0,
                "avg_time_to_complete": 0,
            }

        except Exception as e:
            logger.error(f"Error getting learning path stats: {str(e)}")
            return {}

    def _get_security_event_summary(self, days: int) -> Dict[str, Any]:
        """Get security event summary"""
        try:
            # Get security events from cache
            events = []
            current_time = datetime.now(timezone.utc)

            for i in range(days * 24):  # Check each hour
                hour_key = f"security_events:{int((current_time - timedelta(hours=i)).timestamp() // 3600)}"
                hour_events = cache.get(hour_key, [])
                events.extend(hour_events)

            if not events:
                return {"total_events": 0, "event_types": {}, "severity_breakdown": {}}

            # Analyze events
            event_types = {}
            severity_breakdown = {"low": 0, "medium": 0, "high": 0}

            for event in events:
                event_type = event.get("event_type", "unknown")
                event_types[event_type] = event_types.get(event_type, 0) + 1

                # Classify severity based on event type
                if event_type in ["flag_reuse_attempt", "suspicious_payload"]:
                    severity_breakdown["high"] += 1
                elif event_type in ["rate_limit_exceeded", "invalid_flag_format"]:
                    severity_breakdown["medium"] += 1
                else:
                    severity_breakdown["low"] += 1

            return {
                "total_events": len(events),
                "event_types": event_types,
                "severity_breakdown": severity_breakdown,
                "events_per_day": len(events) / days if days > 0 else 0,
            }

        except Exception as e:
            logger.error(f"Error getting security event summary: {str(e)}")
            return {}

    def _calculate_platform_performance_benchmarks(self) -> Dict[str, Any]:
        """Calculate platform performance benchmarks"""
        try:
            # Get overall platform metrics
            total_challenges = Challenge.query.filter_by(is_active=True).count()
            total_completions = UserChallenge.query.filter_by(completed=True).count()
            total_submissions = Submission.query.count()
            successful_submissions = Submission.query.filter_by(is_correct=True).count()

            # Calculate benchmarks
            avg_completion_rate = (
                (
                    total_completions
                    / (total_challenges * User.query.filter_by(is_active=True).count())
                )
                * 100
                if total_challenges > 0
                else 0
            )
            platform_success_rate = (
                (successful_submissions / total_submissions) * 100
                if total_submissions > 0
                else 0
            )

            return {
                "avg_completion_rate_percent": round(avg_completion_rate, 2),
                "platform_success_rate_percent": round(platform_success_rate, 2),
                "challenges_per_user": round(
                    total_completions / User.query.filter_by(is_active=True).count(), 2
                )
                if User.query.filter_by(is_active=True).count() > 0
                else 0,
                "submissions_per_completion": round(
                    total_submissions / total_completions, 2
                )
                if total_completions > 0
                else 0,
            }

        except Exception as e:
            logger.error(f"Error calculating platform performance benchmarks: {str(e)}")
            return {}

    def _calculate_growth_metrics(self, days: int) -> Dict[str, Any]:
        """Calculate growth metrics for the platform"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            prev_cutoff = cutoff_date - timedelta(days=days)

            # Current period metrics
            current_new_users = User.query.filter(
                User.created_at >= cutoff_date
            ).count()
            current_completions = UserChallenge.query.filter(
                UserChallenge.completed == True,
                UserChallenge.completed_at >= cutoff_date,
            ).count()

            # Previous period metrics
            previous_new_users = User.query.filter(
                User.created_at >= prev_cutoff, User.created_at < cutoff_date
            ).count()
            previous_completions = UserChallenge.query.filter(
                UserChallenge.completed == True,
                UserChallenge.completed_at >= prev_cutoff,
                UserChallenge.completed_at < cutoff_date,
            ).count()

            # Calculate growth rates
            user_growth_rate = (
                ((current_new_users - previous_new_users) / previous_new_users * 100)
                if previous_new_users > 0
                else 0
            )
            completion_growth_rate = (
                (
                    (current_completions - previous_completions)
                    / previous_completions
                    * 100
                )
                if previous_completions > 0
                else 0
            )

            return {
                "user_growth_rate_percent": round(user_growth_rate, 2),
                "completion_growth_rate_percent": round(completion_growth_rate, 2),
                "new_users_current_period": current_new_users,
                "new_users_previous_period": previous_new_users,
                "completions_current_period": current_completions,
                "completions_previous_period": previous_completions,
            }

        except Exception as e:
            logger.error(f"Error calculating growth metrics: {str(e)}")
            return {}

    def _calculate_avg_session_duration(self, days: int) -> float:
        """Calculate average session duration"""
        try:
            # This would require session tracking implementation
            # Placeholder for now
            return 0.0

        except Exception as e:
            logger.error(f"Error calculating avg session duration: {str(e)}")
            return 0.0

    def _get_system_health_metrics(self) -> Dict[str, Any]:
        """Get system health and performance metrics"""
        try:
            # Basic health metrics
            total_users = User.query.count()
            active_challenges = Challenge.query.filter_by(is_active=True).count()

            # Database health (simple check)
            try:
                db.session.execute("SELECT 1")
                db_status = "healthy"
            except:
                db_status = "unhealthy"

            # Cache health
            try:
                cache.set("health_check", "ok", timeout=60)
                cache_result = cache.get("health_check")
                cache_status = "healthy" if cache_result == "ok" else "unhealthy"
            except:
                cache_status = "unhealthy"

            return {
                "database_status": db_status,
                "cache_status": cache_status,
                "total_users": total_users,
                "active_challenges": active_challenges,
                "system_status": "healthy"
                if db_status == "healthy" and cache_status == "healthy"
                else "degraded",
            }

        except Exception as e:
            logger.error(f"Error getting system health metrics: {str(e)}")
            return {"system_status": "unknown"}
