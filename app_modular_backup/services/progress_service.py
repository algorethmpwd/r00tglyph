#!/usr/bin/env python3
"""
Progress Service
===============

This service handles comprehensive user progress tracking including:
- Challenge completion tracking with detailed analytics
- Achievement system with dynamic unlocking
- Learning path progression and recommendations
- Skill assessment and gap analysis
- Personalized learning recommendations
- Streak tracking and engagement metrics
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_

from app import cache, db
from app.models import (
    Achievement,
    Challenge,
    DifficultyLevel,
    LearningPath,
    Submission,
    User,
    UserAchievement,
    UserChallenge,
    UserLearningPath,
)

logger = logging.getLogger(__name__)


class ProgressService:
    """
    Comprehensive progress tracking and analytics service
    """

    def __init__(self):
        self.cache_timeout = 300  # 5 minutes default cache
        self.streak_cache_timeout = 86400  # 24 hours for streak data

    def get_user_progress(self, user_id: int) -> Dict[str, Any]:
        """
        Get comprehensive user progress data

        Args:
            user_id (int): User ID

        Returns:
            Dict[str, Any]: Complete progress information
        """
        try:
            # Check cache first
            cache_key = f"user_progress:{user_id}"
            cached_progress = cache.get(cache_key)
            if cached_progress:
                return cached_progress

            user = User.query.get(user_id)
            if not user:
                return {}

            # Get basic progress stats
            total_challenges = Challenge.query.filter_by(is_active=True).count()
            completed_challenges = UserChallenge.query.filter_by(
                user_id=user_id, completed=True
            ).count()

            # Calculate completion percentage
            completion_percentage = (
                (completed_challenges / total_challenges * 100)
                if total_challenges > 0
                else 0
            )

            # Get category progress
            category_progress = self._get_category_progress(user_id)

            # Get difficulty progress
            difficulty_progress = self._get_difficulty_progress(user_id)

            # Get recent activity
            recent_activity = self._get_recent_activity(user_id, days=7)

            # Get learning streaks
            streak_data = self._get_streak_data(user_id)

            # Get achievements
            achievements = self._get_user_achievements(user_id)

            # Get learning paths
            learning_paths = self._get_user_learning_paths(user_id)

            # Get performance metrics
            performance_metrics = self._get_performance_metrics(user_id)

            # Compile progress data
            progress_data = {
                "user_id": user_id,
                "username": user.username,
                "display_name": user.display_name,
                "level": user.level,
                "total_score": user.total_score,
                "experience_points": user.experience_points,
                "completion_percentage": round(completion_percentage, 2),
                "challenges": {
                    "total": total_challenges,
                    "completed": completed_challenges,
                    "remaining": total_challenges - completed_challenges,
                },
                "category_progress": category_progress,
                "difficulty_progress": difficulty_progress,
                "recent_activity": recent_activity,
                "streak_data": streak_data,
                "achievements": achievements,
                "learning_paths": learning_paths,
                "performance_metrics": performance_metrics,
                "next_recommendations": self._get_next_recommendations(user_id),
                "skill_gaps": self._identify_skill_gaps(user_id),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            # Cache the result
            cache.set(cache_key, progress_data, timeout=self.cache_timeout)

            return progress_data

        except Exception as e:
            logger.error(f"Error getting user progress: {str(e)}")
            return {}

    def _get_category_progress(self, user_id: int) -> Dict[str, Dict[str, Any]]:
        """Get progress breakdown by challenge category"""
        try:
            # Get all categories
            categories = db.session.query(Challenge.category.distinct()).all()
            category_progress = {}

            for (category,) in categories:
                # Get total challenges in category
                total_in_category = Challenge.query.filter_by(
                    category=category, is_active=True
                ).count()

                # Get completed challenges in category
                completed_in_category = (
                    db.session.query(UserChallenge)
                    .join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.category == category,
                        Challenge.is_active == True,
                    )
                    .count()
                )

                # Calculate category-specific metrics
                completion_rate = (
                    (completed_in_category / total_in_category * 100)
                    if total_in_category > 0
                    else 0
                )

                # Get average score in category
                avg_score_query = (
                    db.session.query(func.avg(UserChallenge.points_earned))
                    .join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.category == category,
                    )
                ).scalar()

                avg_score = float(avg_score_query) if avg_score_query else 0

                # Get difficulty distribution
                difficulty_dist = self._get_category_difficulty_distribution(
                    user_id, category
                )

                category_progress[category.value] = {
                    "total": total_in_category,
                    "completed": completed_in_category,
                    "completion_rate": round(completion_rate, 2),
                    "average_score": round(avg_score, 2),
                    "difficulty_distribution": difficulty_dist,
                    "next_level": self._get_next_level_in_category(user_id, category),
                }

            return category_progress

        except Exception as e:
            logger.error(f"Error getting category progress: {str(e)}")
            return {}

    def _get_category_difficulty_distribution(
        self, user_id: int, category: str
    ) -> Dict[str, int]:
        """Get completed challenges distribution by difficulty in category"""
        try:
            distribution = {}

            for difficulty in DifficultyLevel:
                completed_count = (
                    db.session.query(UserChallenge)
                    .join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.category == category,
                        Challenge.difficulty == difficulty,
                    )
                    .count()
                )

                distribution[difficulty.value] = completed_count

            return distribution

        except Exception as e:
            logger.error(f"Error getting difficulty distribution: {str(e)}")
            return {}

    def _get_next_level_in_category(
        self, user_id: int, category: str
    ) -> Optional[Dict[str, Any]]:
        """Get next recommended level in category"""
        try:
            # Get user's completed challenges in category
            completed_levels = (
                db.session.query(Challenge.level)
                .join(UserChallenge)
                .filter(
                    UserChallenge.user_id == user_id,
                    UserChallenge.completed == True,
                    Challenge.category == category,
                    Challenge.is_active == True,
                )
                .all()
            )

            completed_level_numbers = [level[0] for level in completed_levels]

            if not completed_level_numbers:
                # User hasn't completed any levels, recommend level 1
                next_challenge = Challenge.query.filter_by(
                    category=category, level=1, is_active=True
                ).first()
            else:
                # Find the next sequential level
                max_completed = max(completed_level_numbers)
                next_level = max_completed + 1

                next_challenge = Challenge.query.filter_by(
                    category=category, level=next_level, is_active=True
                ).first()

            if next_challenge:
                return {
                    "id": next_challenge.id,
                    "level": next_challenge.level,
                    "title": next_challenge.title,
                    "difficulty": next_challenge.difficulty.value,
                    "points": next_challenge.base_points,
                }

            return None

        except Exception as e:
            logger.error(f"Error getting next level: {str(e)}")
            return None

    def _get_difficulty_progress(self, user_id: int) -> Dict[str, Dict[str, Any]]:
        """Get progress breakdown by difficulty level"""
        try:
            difficulty_progress = {}

            for difficulty in DifficultyLevel:
                # Get total challenges at this difficulty
                total_at_difficulty = Challenge.query.filter_by(
                    difficulty=difficulty, is_active=True
                ).count()

                # Get completed challenges at this difficulty
                completed_at_difficulty = (
                    db.session.query(UserChallenge)
                    .join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.difficulty == difficulty,
                        Challenge.is_active == True,
                    )
                    .count()
                )

                completion_rate = (
                    (completed_at_difficulty / total_at_difficulty * 100)
                    if total_at_difficulty > 0
                    else 0
                )

                # Get average attempts for this difficulty
                avg_attempts_query = (
                    db.session.query(func.avg(UserChallenge.attempts_count))
                    .join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.difficulty == difficulty,
                    )
                ).scalar()

                avg_attempts = float(avg_attempts_query) if avg_attempts_query else 0

                difficulty_progress[difficulty.value] = {
                    "total": total_at_difficulty,
                    "completed": completed_at_difficulty,
                    "completion_rate": round(completion_rate, 2),
                    "average_attempts": round(avg_attempts, 2),
                }

            return difficulty_progress

        except Exception as e:
            logger.error(f"Error getting difficulty progress: {str(e)}")
            return {}

    def _get_recent_activity(self, user_id: int, days: int = 7) -> List[Dict[str, Any]]:
        """Get recent user activity"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            # Get recent completions
            recent_completions = (
                db.session.query(UserChallenge, Challenge)
                .join(Challenge)
                .filter(
                    UserChallenge.user_id == user_id,
                    UserChallenge.completed == True,
                    UserChallenge.completed_at >= cutoff_date,
                )
                .order_by(desc(UserChallenge.completed_at))
                .limit(20)
                .all()
            )

            activity = []
            for user_challenge, challenge in recent_completions:
                activity.append(
                    {
                        "type": "challenge_completed",
                        "timestamp": user_challenge.completed_at.isoformat(),
                        "challenge": {
                            "id": challenge.id,
                            "title": challenge.title,
                            "category": challenge.category.value,
                            "level": challenge.level,
                            "difficulty": challenge.difficulty.value,
                        },
                        "points_earned": user_challenge.points_earned,
                        "time_spent": user_challenge.time_spent,
                        "attempts": user_challenge.attempts_count,
                    }
                )

            return activity

        except Exception as e:
            logger.error(f"Error getting recent activity: {str(e)}")
            return []

    def _get_streak_data(self, user_id: int) -> Dict[str, Any]:
        """Get user learning streak information"""
        try:
            cache_key = f"streak_data:{user_id}"
            cached_streaks = cache.get(cache_key)
            if cached_streaks:
                return cached_streaks

            user = User.query.get(user_id)
            if not user:
                return {}

            # Get all completion dates
            completion_dates = (
                db.session.query(func.date(UserChallenge.completed_at))
                .filter(
                    UserChallenge.user_id == user_id,
                    UserChallenge.completed == True,
                )
                .distinct()
                .order_by(desc(func.date(UserChallenge.completed_at)))
                .all()
            )

            if not completion_dates:
                return {
                    "current_streak": 0,
                    "longest_streak": 0,
                    "last_activity": None,
                    "streak_start": None,
                }

            # Calculate current streak
            dates = [date[0] for date in completion_dates]
            today = datetime.now(timezone.utc).date()
            yesterday = today - timedelta(days=1)

            current_streak = 0
            streak_start = None

            # Check if user was active today or yesterday
            if dates[0] == today or dates[0] == yesterday:
                current_streak = 1
                streak_start = dates[0]

                # Count consecutive days
                for i in range(1, len(dates)):
                    if dates[i - 1] - dates[i] == timedelta(days=1):
                        current_streak += 1
                        streak_start = dates[i]
                    else:
                        break

            # Calculate longest streak
            longest_streak = 0
            temp_streak = 1

            for i in range(1, len(dates)):
                if dates[i - 1] - dates[i] == timedelta(days=1):
                    temp_streak += 1
                else:
                    longest_streak = max(longest_streak, temp_streak)
                    temp_streak = 1

            longest_streak = max(longest_streak, temp_streak)

            streak_data = {
                "current_streak": current_streak,
                "longest_streak": longest_streak,
                "last_activity": dates[0].isoformat() if dates else None,
                "streak_start": streak_start.isoformat() if streak_start else None,
                "total_active_days": len(dates),
            }

            # Cache for 24 hours
            cache.set(cache_key, streak_data, timeout=self.streak_cache_timeout)

            return streak_data

        except Exception as e:
            logger.error(f"Error getting streak data: {str(e)}")
            return {}

    def _get_user_achievements(self, user_id: int) -> Dict[str, Any]:
        """Get user achievements and progress"""
        try:
            # Get unlocked achievements
            unlocked_achievements = (
                db.session.query(UserAchievement, Achievement)
                .join(Achievement)
                .filter(UserAchievement.user_id == user_id)
                .order_by(desc(UserAchievement.unlocked_at))
                .all()
            )

            unlocked = []
            for user_achievement, achievement in unlocked_achievements:
                unlocked.append(
                    {
                        "id": achievement.id,
                        "name": achievement.name,
                        "description": achievement.description,
                        "category": achievement.category,
                        "difficulty": achievement.difficulty.value,
                        "points_reward": achievement.points_reward,
                        "unlocked_at": user_achievement.unlocked_at.isoformat(),
                        "icon": achievement.icon,
                    }
                )

            # Get available achievements (not yet unlocked)
            unlocked_ids = [ua.achievement_id for ua, _ in unlocked_achievements]

            available_achievements = Achievement.query.filter(
                Achievement.is_active == True,
                ~Achievement.id.in_(unlocked_ids),
                Achievement.is_hidden == False,
            ).all()

            available = []
            for achievement in available_achievements:
                progress = self._calculate_achievement_progress(user_id, achievement)
                available.append(
                    {
                        "id": achievement.id,
                        "name": achievement.name,
                        "description": achievement.description,
                        "category": achievement.category,
                        "difficulty": achievement.difficulty.value,
                        "points_reward": achievement.points_reward,
                        "progress_percentage": progress,
                        "icon": achievement.icon,
                    }
                )

            return {
                "unlocked": unlocked,
                "available": available,
                "total_unlocked": len(unlocked),
                "total_available": len(available),
                "completion_rate": (
                    len(unlocked) / (len(unlocked) + len(available)) * 100
                    if (len(unlocked) + len(available)) > 0
                    else 0
                ),
            }

        except Exception as e:
            logger.error(f"Error getting user achievements: {str(e)}")
            return {}

    def _calculate_achievement_progress(
        self, user_id: int, achievement: Achievement
    ) -> float:
        """Calculate progress towards a specific achievement"""
        try:
            conditions = achievement.unlock_conditions

            if not conditions:
                return 0.0

            # Different achievement types
            if achievement.category == "completion":
                return self._calculate_completion_achievement_progress(
                    user_id, conditions
                )
            elif achievement.category == "speed":
                return self._calculate_speed_achievement_progress(user_id, conditions)
            elif achievement.category == "streak":
                return self._calculate_streak_achievement_progress(user_id, conditions)
            elif achievement.category == "score":
                return self._calculate_score_achievement_progress(user_id, conditions)

            return 0.0

        except Exception as e:
            logger.error(f"Error calculating achievement progress: {str(e)}")
            return 0.0

    def _calculate_completion_achievement_progress(
        self, user_id: int, conditions: Dict
    ) -> float:
        """Calculate progress for completion-based achievements"""
        target = conditions.get("target", 1)
        category = conditions.get("category")
        difficulty = conditions.get("difficulty")

        query = UserChallenge.query.filter(
            UserChallenge.user_id == user_id,
            UserChallenge.completed == True,
        )

        if category:
            query = query.join(Challenge).filter(Challenge.category == category)

        if difficulty:
            query = query.join(Challenge).filter(Challenge.difficulty == difficulty)

        current = query.count()

        return min(100.0, (current / target) * 100)

    def _calculate_speed_achievement_progress(
        self, user_id: int, conditions: Dict
    ) -> float:
        """Calculate progress for speed-based achievements"""
        target_time = conditions.get("target_time_minutes", 60)
        challenge_count = conditions.get("challenge_count", 1)

        # Count challenges completed within target time
        fast_completions = UserChallenge.query.filter(
            UserChallenge.user_id == user_id,
            UserChallenge.completed == True,
            UserChallenge.time_spent <= target_time * 60,  # Convert to seconds
        ).count()

        return min(100.0, (fast_completions / challenge_count) * 100)

    def _calculate_streak_achievement_progress(
        self, user_id: int, conditions: Dict
    ) -> float:
        """Calculate progress for streak-based achievements"""
        target_streak = conditions.get("target_streak", 7)
        streak_data = self._get_streak_data(user_id)
        current_streak = streak_data.get("current_streak", 0)

        return min(100.0, (current_streak / target_streak) * 100)

    def _calculate_score_achievement_progress(
        self, user_id: int, conditions: Dict
    ) -> float:
        """Calculate progress for score-based achievements"""
        target_score = conditions.get("target_score", 1000)
        user = User.query.get(user_id)

        if not user:
            return 0.0

        return min(100.0, (user.total_score / target_score) * 100)

    def _get_user_learning_paths(self, user_id: int) -> Dict[str, Any]:
        """Get user's learning path progress"""
        try:
            # Get active learning paths for user
            user_paths = (
                db.session.query(UserLearningPath, LearningPath)
                .join(LearningPath)
                .filter(
                    UserLearningPath.user_id == user_id,
                    LearningPath.is_active == True,
                )
                .all()
            )

            active_paths = []
            for user_path, learning_path in user_paths:
                progress_percentage = user_path.get_progress_percentage()
                next_challenge = user_path.get_next_challenge()

                active_paths.append(
                    {
                        "id": learning_path.id,
                        "name": learning_path.name,
                        "description": learning_path.description,
                        "difficulty": learning_path.difficulty.value,
                        "estimated_hours": learning_path.estimated_hours,
                        "progress_percentage": progress_percentage,
                        "challenges_completed": user_path.challenges_completed,
                        "total_challenges": len(learning_path.challenge_sequence),
                        "current_challenge_index": user_path.current_challenge_index,
                        "next_challenge": {
                            "id": next_challenge.id,
                            "title": next_challenge.title,
                            "level": next_challenge.level,
                            "category": next_challenge.category.value,
                        }
                        if next_challenge
                        else None,
                        "started_at": user_path.started_at.isoformat(),
                        "completed_at": user_path.completed_at.isoformat()
                        if user_path.completed_at
                        else None,
                        "time_spent": user_path.time_spent,
                    }
                )

            # Get recommended learning paths
            recommended_paths = self._get_recommended_learning_paths(user_id)

            return {
                "active": active_paths,
                "recommended": recommended_paths,
                "completed_count": len(
                    [p for p in active_paths if p["progress_percentage"] == 100]
                ),
            }

        except Exception as e:
            logger.error(f"Error getting learning paths: {str(e)}")
            return {}

    def _get_recommended_learning_paths(self, user_id: int) -> List[Dict[str, Any]]:
        """Get recommended learning paths based on user's progress"""
        try:
            # Get user's completed challenges to analyze skill gaps
            completed_challenges = (
                db.session.query(Challenge)
                .join(UserChallenge)
                .filter(
                    UserChallenge.user_id == user_id,
                    UserChallenge.completed == True,
                )
                .all()
            )

            # Analyze user's strengths and weaknesses
            category_completion = {}
            for challenge in completed_challenges:
                cat = challenge.category.value
                if cat not in category_completion:
                    category_completion[cat] = {"completed": 0, "total": 0}
                category_completion[cat]["completed"] += 1

            # Get total challenges per category
            for category in category_completion:
                total = Challenge.query.filter_by(
                    category=category, is_active=True
                ).count()
                category_completion[category]["total"] = total

            # Find categories where user needs improvement
            weak_categories = []
            for category, stats in category_completion.items():
                completion_rate = (
                    stats["completed"] / stats["total"] if stats["total"] > 0 else 0
                )
                if completion_rate < 0.5:  # Less than 50% completion
                    weak_categories.append(category)

            # Get learning paths that target weak areas
            recommended = []
            learning_paths = LearningPath.query.filter_by(is_active=True).all()

            for path in learning_paths:
                # Check if path addresses weak areas
                path_categories = set()
                for challenge_id in path.challenge_sequence:
                    challenge = Challenge.query.get(challenge_id)
                    if challenge:
                        path_categories.add(challenge.category.value)

                if any(cat in weak_categories for cat in path_categories):
                    recommended.append(
                        {
                            "id": path.id,
                            "name": path.name,
                            "description": path.description,
                            "difficulty": path.difficulty.value,
                            "estimated_hours": path.estimated_hours,
                            "total_challenges": len(path.challenge_sequence),
                            "target_categories": list(path_categories),
                            "completion_rate": path.get_completion_rate(),
                            "is_featured": path.is_featured,
                        }
                    )

            # Sort by relevance (featured first, then by difficulty match)
            user = User.query.get(user_id)
            user_level = user.level if user else 1

            recommended.sort(
                key=lambda x: (
                    -x["is_featured"],  # Featured paths first
                    abs(
                        user_level
                        - ["beginner", "intermediate", "advanced", "expert"].index(
                            x["difficulty"]
                        )
                    ),
                    -x["completion_rate"],  # Popular paths
                )
            )

            return recommended[:5]  # Return top 5 recommendations

        except Exception as e:
            logger.error(f"Error getting recommended learning paths: {str(e)}")
            return []

    def _get_performance_metrics(self, user_id: int) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        try:
            # Get all user's completed challenges
            completed_challenges = UserChallenge.query.filter_by(
                user_id=user_id, completed=True
            ).all()

            if not completed_challenges:
                return {}

            # Calculate metrics
            total_time = sum(
                uc.time_spent for uc in completed_challenges if uc.time_spent
            )
            total_attempts = sum(uc.attempts_count for uc in completed_challenges)
            total_hints = sum(uc.hints_used for uc in completed_challenges)
            total_points = sum(uc.points_earned for uc in completed_challenges)

            avg_time = (
                total_time / len(completed_challenges) if completed_challenges else 0
            )
            avg_attempts = (
                total_attempts / len(completed_challenges)
                if completed_challenges
                else 0
            )
            avg_hints = (
                total_hints / len(completed_challenges) if completed_challenges else 0
            )

            # Get success rate (successful submissions vs total submissions)
            total_submissions = Submission.query.filter_by(user_id=user_id).count()
            successful_submissions = Submission.query.filter_by(
                user_id=user_id, is_correct=True
            ).count()

            success_rate = (
                (successful_submissions / total_submissions * 100)
                if total_submissions > 0
                else 0
            )

            return {
                "challenges_completed": len(completed_challenges),
                "total_time_spent": total_time,
                "total_attempts": total_attempts,
                "total_hints_used": total_hints,
                "total_points_earned": total_points,
                "average_time_per_challenge": round(
                    avg_time / 60, 2
                ),  # Convert to minutes
                "average_attempts_per_challenge": round(avg_attempts, 2),
                "average_hints_per_challenge": round(avg_hints, 2),
                "success_rate": round(success_rate, 2),
                "efficiency_score": self._calculate_efficiency_score(
                    avg_attempts, avg_hints, success_rate
                ),
            }

        except Exception as e:
            logger.error(f"Error getting performance metrics: {str(e)}")
            return {}

    def _calculate_efficiency_score(
        self, avg_attempts: float, avg_hints: float, success_rate: float
    ) -> float:
        """Calculate user efficiency score (0-100)"""
        try:
            # Lower attempts and hints = higher efficiency
            attempt_score = max(
                0, 100 - (avg_attempts - 1) * 20
            )  # Penalty after first attempt
            hint_score = max(0, 100 - avg_hints * 15)  # Penalty for each hint
            success_score = success_rate  # Direct success rate

            # Weighted average
            efficiency = attempt_score * 0.4 + hint_score * 0.3 + success_score * 0.3

            return round(min(100, max(0, efficiency)), 2)

        except Exception as e:
            logger.error(f"Error calculating efficiency score: {str(e)}")
            return 0.0

    def _get_next_recommendations(self, user_id: int) -> List[Dict[str, Any]]:
        """Get next challenge recommendations for user"""
        try:
            # Get user's completed challenges
            completed_challenge_ids = [
                uc.challenge_id
                for uc in UserChallenge.query.filter_by(
                    user_id=user_id, completed=True
                ).all()
            ]

            # Get available challenges (not completed)
            available_challenges = Challenge.query.filter(
                Challenge.is_active == True,
                ~Challenge.id.in_(completed_challenge_ids),
            ).all()

            # Filter by prerequisites
            user = User.query.get(user_id)
            accessible_challenges = [
                c for c in available_challenges if user.can_access_challenge(c)
            ]

            # Score and rank recommendations
            recommendations = []
            for challenge in accessible_challenges:
                score = self._calculate_recommendation_score(user_id, challenge)

                recommendations.append(
                    {
                        "challenge": {
                            "id": challenge.id,
                            "title": challenge.title,
                            "category": challenge.category.value,
                            "level": challenge.level,
                            "difficulty": challenge.difficulty.value,
                            "points": challenge.base_points,
                            "description": challenge.description,
                        },
                        "recommendation_score": score,
                        "reason": self._get_recommendation_reason(user_id, challenge),
                    }
                )

            # Sort by recommendation score
            recommendations.sort(key=lambda x: x["recommendation_score"], reverse=True)

            return recommendations[:10]  # Return top 10 recommendations

        except Exception as e:
            logger.error(f"Error getting next recommendations: {str(e)}")
            return []

    def _calculate_recommendation_score(
        self, user_id: int, challenge: Challenge
    ) -> float:
        """Calculate recommendation score for a challenge"""
        try:
            score = 0.0

            # Category preference (user's weakest areas get higher scores)
            category_progress = self._get_category_progress(user_id)
            category_completion = category_progress.get(
                challenge.category.value, {}
            ).get("completion_rate", 0)
            score += (100 - category_completion) * 0.3  # Weight: 30%

            # Difficulty appropriateness
            user = User.query.get(user_id)
            user_level = user.level if user else 1

            difficulty_mapping = {
                DifficultyLevel.BEGINNER: 1,
                DifficultyLevel.INTERMEDIATE: 2,
                DifficultyLevel.ADVANCED: 3,
                DifficultyLevel.EXPERT: 4,
            }

            challenge_difficulty = difficulty_mapping.get(challenge.difficulty, 2)
            difficulty_diff = abs(user_level - challenge_difficulty)
            difficulty_score = max(0, 100 - difficulty_diff * 25)
            score += difficulty_score * 0.4  # Weight: 40%

            # Challenge popularity (success rate)
            popularity_score = (
                challenge.get_success_rate()
                if hasattr(challenge, "get_success_rate")
                else 50
            )
            score += popularity_score * 0.2  # Weight: 20%

            # Sequential progression bonus
            if challenge.level == 1:  # First level in category
                score += 20
            else:
                # Check if previous levels are completed
                prev_level_completed = (
                    UserChallenge.query.join(Challenge)
                    .filter(
                        UserChallenge.user_id == user_id,
                        UserChallenge.completed == True,
                        Challenge.category == challenge.category,
                        Challenge.level == challenge.level - 1,
                    )
                    .first()
                )

                if prev_level_completed:
                    score += 15  # Sequential bonus

            return min(100.0, max(0.0, score))

        except Exception as e:
            logger.error(f"Error calculating recommendation score: {str(e)}")
            return 0.0

    def _get_recommendation_reason(self, user_id: int, challenge: Challenge) -> str:
        """Get human-readable reason for recommendation"""
        try:
            category_progress = self._get_category_progress(user_id)
            category_completion = category_progress.get(
                challenge.category.value, {}
            ).get("completion_rate", 0)

            if category_completion < 30:
                return f"Strengthen your {challenge.category.value.upper()} skills"
            elif challenge.level == 1:
                return f"Start your {challenge.category.value.upper()} journey"
            elif category_completion < 70:
                return f"Continue building {challenge.category.value.upper()} expertise"
            else:
                return f"Master advanced {challenge.category.value.upper()} techniques"

        except Exception as e:
            logger.error(f"Error getting recommendation reason: {str(e)}")
            return "Recommended for skill development"

    def _identify_skill_gaps(self, user_id: int) -> List[Dict[str, Any]]:
        """Identify user's skill gaps and learning opportunities"""
        try:
            category_progress = self._get_category_progress(user_id)
            difficulty_progress = self._get_difficulty_progress(user_id)

            skill_gaps = []

            # Category gaps
            for category, progress in category_progress.items():
                if progress["completion_rate"] < 50:
                    skill_gaps.append(
                        {
                            "type": "category",
                            "area": category,
                            "gap_level": "high"
                            if progress["completion_rate"] < 25
                            else "medium",
                            "completion_rate": progress["completion_rate"],
                            "recommendation": f"Focus on {category.upper()} fundamentals",
                            "next_challenge": progress.get("next_level"),
                        }
                    )

            # Difficulty gaps
            for difficulty, progress in difficulty_progress.items():
                if progress["completion_rate"] < 30 and difficulty != "expert":
                    skill_gaps.append(
                        {
                            "type": "difficulty",
                            "area": difficulty,
                            "gap_level": "medium",
                            "completion_rate": progress["completion_rate"],
                            "recommendation": f"Practice more {difficulty} level challenges",
                        }
                    )

            return skill_gaps

        except Exception as e:
            logger.error(f"Error identifying skill gaps: {str(e)}")
            return []

    def update_user_progress(self, user_id: int, challenge_id: int) -> bool:
        """
        Update user progress after challenge completion

        Args:
            user_id (int): User ID
            challenge_id (int): Completed challenge ID

        Returns:
            bool: Success status
        """
        try:
            # Clear cached progress data
            cache_key = f"user_progress:{user_id}"
            cache.delete(cache_key)

            # Clear streak cache
            streak_cache_key = f"streak_data:{user_id}"
            cache.delete(streak_cache_key)

            # Check for achievement unlocks
            self._check_achievement_unlocks(user_id)

            # Update learning path progress
            self._update_learning_path_progress(user_id, challenge_id)

            # Update user level if needed
            self._update_user_level(user_id)

            logger.info(
                f"Updated progress for user {user_id}, challenge {challenge_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Error updating user progress: {str(e)}")
            return False

    def _check_achievement_unlocks(self, user_id: int) -> List[Achievement]:
        """Check and unlock any new achievements for user"""
        try:
            # Get user's current achievements
            unlocked_achievement_ids = [
                ua.achievement_id
                for ua in UserAchievement.query.filter_by(user_id=user_id).all()
            ]

            # Get available achievements
            available_achievements = Achievement.query.filter(
                Achievement.is_active == True,
                ~Achievement.id.in_(unlocked_achievement_ids),
            ).all()

            newly_unlocked = []

            for achievement in available_achievements:
                progress = self._calculate_achievement_progress(user_id, achievement)

                if progress >= 100.0:
                    # Unlock achievement
                    user_achievement = UserAchievement(
                        user_id=user_id,
                        achievement_id=achievement.id,
                        progress_when_unlocked=self.get_user_progress(user_id),
                    )

                    db.session.add(user_achievement)

                    # Award points
                    user = User.query.get(user_id)
                    if user and achievement.points_reward > 0:
                        user.total_score += achievement.points_reward
                        user.experience_points += achievement.points_reward

                    newly_unlocked.append(achievement)

            if newly_unlocked:
                db.session.commit()
                logger.info(
                    f"Unlocked {len(newly_unlocked)} achievements for user {user_id}"
                )

            return newly_unlocked

        except Exception as e:
            logger.error(f"Error checking achievement unlocks: {str(e)}")
            return []

    def _update_learning_path_progress(self, user_id: int, challenge_id: int) -> None:
        """Update learning path progress when challenge is completed"""
        try:
            # Find learning paths that include this challenge
            user_learning_paths = UserLearningPath.query.filter_by(
                user_id=user_id, completed=False
            ).all()

            for user_path in user_learning_paths:
                learning_path = user_path.learning_path

                if challenge_id in learning_path.challenge_sequence:
                    # Check if this is the next expected challenge
                    expected_challenge_id = learning_path.challenge_sequence[
                        user_path.current_challenge_index
                    ]

                    if challenge_id == expected_challenge_id:
                        user_path.advance_to_next_challenge()

            db.session.commit()

        except Exception as e:
            logger.error(f"Error updating learning path progress: {str(e)}")

    def _update_user_level(self, user_id: int) -> None:
        """Update user level based on completion and score"""
        try:
            user = User.query.get(user_id)
            if not user:
                return

            # Calculate level based on experience points and completion rate
            completion_percentage = user.get_completion_percentage()
            experience_points = user.experience_points

            # Level calculation formula
            new_level = 1
            if experience_points >= 10000 and completion_percentage >= 80:
                new_level = 4  # Expert
            elif experience_points >= 5000 and completion_percentage >= 60:
                new_level = 3  # Advanced
            elif experience_points >= 2000 and completion_percentage >= 30:
                new_level = 2  # Intermediate
            # else remains 1 (Beginner)

            if new_level > user.level:
                user.level = new_level
                db.session.commit()
                logger.info(f"User {user_id} leveled up to {new_level}")

        except Exception as e:
            logger.error(f"Error updating user level: {str(e)}")

    def get_global_stats(self) -> Dict[str, Any]:
        """Get global platform statistics"""
        try:
            cache_key = "global_stats"
            cached_stats = cache.get(cache_key)
            if cached_stats:
                return cached_stats

            # Basic counts
            total_users = User.query.filter_by(is_active=True).count()
            total_challenges = Challenge.query.filter_by(is_active=True).count()
            total_completions = UserChallenge.query.filter_by(completed=True).count()
            total_submissions = Submission.query.count()

            # Active users (last 30 days)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
            active_users = User.query.filter(User.last_active >= cutoff_date).count()

            # Success rate
            successful_submissions = Submission.query.filter_by(is_correct=True).count()
            success_rate = (
                (successful_submissions / total_submissions * 100)
                if total_submissions > 0
                else 0
            )

            # Popular challenges
            popular_challenges = (
                db.session.query(
                    Challenge, func.count(UserChallenge.id).label("completion_count")
                )
                .join(UserChallenge)
                .filter(UserChallenge.completed == True)
                .group_by(Challenge.id)
                .order_by(desc("completion_count"))
                .limit(5)
                .all()
            )

            popular_list = [
                {
                    "title": challenge.title,
                    "category": challenge.category.value,
                    "level": challenge.level,
                    "completions": count,
                }
                for challenge, count in popular_challenges
            ]

            # Top performers
            top_users = (
                User.query.filter_by(is_active=True)
                .order_by(desc(User.total_score))
                .limit(5)
                .all()
            )

            leaderboard = [
                {
                    "username": user.username,
                    "display_name": user.display_name,
                    "score": user.total_score,
                    "level": user.level,
                    "completion_percentage": user.get_completion_percentage(),
                }
                for user in top_users
            ]

            global_stats = {
                "total_users": total_users,
                "active_users": active_users,
                "total_challenges": total_challenges,
                "total_completions": total_completions,
                "total_submissions": total_submissions,
                "success_rate": round(success_rate, 2),
                "popular_challenges": popular_list,
                "leaderboard": leaderboard,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            # Cache for 5 minutes
            cache.set(cache_key, global_stats, timeout=300)

            return global_stats

        except Exception as e:
            logger.error(f"Error getting global stats: {str(e)}")
            return {}

    def get_category_progress(self, user_id: int, category: str) -> Dict[str, Any]:
        """Get detailed progress for specific category"""
        try:
            category_progress = self._get_category_progress(user_id)
            return category_progress.get(category, {})

        except Exception as e:
            logger.error(f"Error getting category progress: {str(e)}")
            return {}
