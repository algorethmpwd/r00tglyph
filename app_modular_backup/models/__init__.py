#!/usr/bin/env python3
"""
R00tGlyph Database Models
========================

This module contains all database models with proper normalization,
relationships, and validation. Models are designed for scalability
and maintainability.
"""

from datetime import datetime, timezone
from enum import Enum

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class DifficultyLevel(Enum):
    """Enumeration for challenge difficulty levels"""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ChallengeCategory(Enum):
    """Enumeration for challenge categories"""

    XSS = "xss"
    SQLI = "sqli"
    CMDI = "cmdi"
    CSRF = "csrf"
    SSRF = "ssrf"
    SSTI = "ssti"
    DESERIAL = "deserial"
    AUTH = "auth"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    IDOR = "idor"


class UserRole(Enum):
    """Enumeration for user roles"""

    STUDENT = "student"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"


# Association table for team memberships
team_members = db.Table(
    "team_members",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
    db.Column("team_id", db.Integer, db.ForeignKey("teams.id"), primary_key=True),
    db.Column("joined_at", db.DateTime, default=lambda: datetime.now(timezone.utc)),
    db.Column("is_leader", db.Boolean, default=False),
)


class User(db.Model):
    """
    User model with enhanced features for security training platform
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # Profile information
    display_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(256), nullable=True)

    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.STUDENT)

    # Scoring and progress
    total_score = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    experience_points = db.Column(db.Integer, default=0)
    streak_days = db.Column(db.Integer, default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_active = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    # Preferences
    preferred_theme = db.Column(db.String(20), default="dark")
    notifications_enabled = db.Column(db.Boolean, default=True)
    email_notifications = db.Column(db.Boolean, default=True)

    # Security settings
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)

    # Relationships
    challenge_attempts = db.relationship(
        "UserChallenge", backref="user", lazy="dynamic"
    )
    submissions = db.relationship("Submission", backref="user", lazy="dynamic")
    flags = db.relationship("Flag", backref="user", lazy="dynamic")
    achievements = db.relationship("UserAchievement", backref="user", lazy="dynamic")
    learning_paths = db.relationship("UserLearningPath", backref="user", lazy="dynamic")
    teams = db.relationship("Team", secondary=team_members, back_populates="members")

    def set_password(self, password):
        """Set user password with proper hashing"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)

    def get_completion_percentage(self):
        """Calculate overall completion percentage"""
        total_challenges = Challenge.query.filter_by(is_active=True).count()
        if total_challenges == 0:
            return 0
        completed_challenges = self.challenge_attempts.filter_by(completed=True).count()
        return round((completed_challenges / total_challenges) * 100, 2)

    def get_category_progress(self, category):
        """Get progress for specific challenge category"""
        category_challenges = Challenge.query.filter_by(
            category=category, is_active=True
        ).count()

        if category_challenges == 0:
            return {"completed": 0, "total": 0, "percentage": 0}

        completed = (
            db.session.query(UserChallenge)
            .join(Challenge)
            .filter(
                UserChallenge.user_id == self.id,
                UserChallenge.completed == True,
                Challenge.category == category,
            )
            .count()
        )

        return {
            "completed": completed,
            "total": category_challenges,
            "percentage": round((completed / category_challenges) * 100, 2),
        }

    def can_access_challenge(self, challenge):
        """Check if user can access a specific challenge based on prerequisites"""
        if not challenge.prerequisites:
            return True

        for prereq_id in challenge.prerequisites:
            prereq_completed = UserChallenge.query.filter_by(
                user_id=self.id, challenge_id=prereq_id, completed=True
            ).first()

            if not prereq_completed:
                return False

        return True

    def update_last_active(self):
        """Update user's last active timestamp"""
        self.last_active = datetime.now(timezone.utc)
        db.session.commit()

    def __repr__(self):
        return f"<User {self.username}>"


class Team(db.Model):
    """Team model for collaborative learning"""

    __tablename__ = "teams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)

    # Team settings
    is_private = db.Column(db.Boolean, default=False)
    max_members = db.Column(db.Integer, default=10)
    invite_code = db.Column(db.String(20), unique=True, nullable=True)

    # Progress sharing
    shared_progress = db.Column(db.Boolean, default=False)
    competition_mode = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    members = db.relationship("User", secondary=team_members, back_populates="teams")

    def get_team_score(self):
        """Calculate combined team score"""
        return sum(member.total_score for member in self.members)

    def get_leader(self):
        """Get team leader"""
        leader_row = db.session.execute(
            team_members.select().where(
                team_members.c.team_id == self.id, team_members.c.is_leader == True
            )
        ).first()

        if leader_row:
            return User.query.get(leader_row.user_id)
        return None

    def __repr__(self):
        return f"<Team {self.name}>"


class Challenge(db.Model):
    """Enhanced challenge model with detailed metadata"""

    __tablename__ = "challenges"

    id = db.Column(db.Integer, primary_key=True)

    # Basic information
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    category = db.Column(db.Enum(ChallengeCategory), nullable=False, index=True)
    difficulty = db.Column(db.Enum(DifficultyLevel), nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False)  # 1-23 within category

    # Content
    description = db.Column(db.Text, nullable=False)
    learning_objectives = db.Column(db.Text, nullable=True)
    scenario = db.Column(db.Text, nullable=True)

    # Scoring
    base_points = db.Column(db.Integer, default=100)
    bonus_points = db.Column(db.Integer, default=0)  # For speed completion, etc.

    # Challenge configuration
    time_limit = db.Column(db.Integer, nullable=True)  # in minutes, null = no limit
    max_attempts = db.Column(db.Integer, default=0)  # 0 = unlimited
    hints_allowed = db.Column(db.Integer, default=3)

    # Prerequisites and dependencies
    prerequisites = db.Column(db.JSON, default=list)  # List of challenge IDs
    unlocks = db.Column(db.JSON, default=list)  # Challenges this unlocks

    # Tool requirements
    required_tools = db.Column(db.JSON, default=list)  # e.g., ['burp', 'sqlmap']
    recommended_tools = db.Column(db.JSON, default=list)

    # Vulnerable application settings
    has_docker_app = db.Column(db.Boolean, default=False)
    docker_image = db.Column(db.String(200), nullable=True)
    app_port = db.Column(db.Integer, nullable=True)
    app_config = db.Column(db.JSON, default=dict)

    # Status and visibility
    is_active = db.Column(db.Boolean, default=True)
    is_beta = db.Column(db.Boolean, default=False)
    release_date = db.Column(db.DateTime, nullable=True)

    # Analytics
    total_attempts = db.Column(db.Integer, default=0)
    successful_attempts = db.Column(db.Integer, default=0)
    average_completion_time = db.Column(db.Float, nullable=True)  # in minutes

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user_attempts = db.relationship(
        "UserChallenge", backref="challenge", lazy="dynamic"
    )
    submissions = db.relationship("Submission", backref="challenge", lazy="dynamic")
    flags = db.relationship("Flag", backref="challenge", lazy="dynamic")
    hints = db.relationship("Hint", backref="challenge", lazy="dynamic")

    def get_success_rate(self):
        """Calculate challenge success rate"""
        if self.total_attempts == 0:
            return 0
        return round((self.successful_attempts / self.total_attempts) * 100, 2)

    def get_difficulty_score(self):
        """Calculate difficulty score based on success rate and average time"""
        success_rate = self.get_success_rate()
        if success_rate == 0:
            return 10  # Max difficulty if no one completed

        # Lower success rate = higher difficulty
        base_difficulty = (100 - success_rate) / 10

        # Factor in completion time if available
        if self.average_completion_time:
            time_factor = min(self.average_completion_time / 60, 2)  # Cap at 2x
            return min(base_difficulty * time_factor, 10)

        return base_difficulty

    def is_accessible_to_user(self, user):
        """Check if challenge is accessible to specific user"""
        if not self.is_active:
            return False

        return user.can_access_challenge(self)

    def __repr__(self):
        return f"<Challenge {self.category.value}-{self.level}: {self.title}>"


class UserChallenge(db.Model):
    """Association model for user challenge attempts with detailed tracking"""

    __tablename__ = "user_challenges"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)

    # Progress tracking
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    completed = db.Column(db.Boolean, default=False)

    # Attempt details
    attempts_count = db.Column(db.Integer, default=0)
    hints_used = db.Column(db.Integer, default=0)
    time_spent = db.Column(db.Integer, default=0)  # in seconds

    # Scoring
    points_earned = db.Column(db.Integer, default=0)
    bonus_earned = db.Column(db.Integer, default=0)

    # Analytics
    first_attempt_at = db.Column(db.DateTime, nullable=True)
    last_attempt_at = db.Column(db.DateTime, nullable=True)
    success_method = db.Column(
        db.String(100), nullable=True
    )  # e.g., 'manual', 'tool-assisted'

    # Constraints
    __table_args__ = (
        db.UniqueConstraint("user_id", "challenge_id", name="unique_user_challenge"),
    )

    def mark_completed(self, points=None, bonus=0, method=None):
        """Mark challenge as completed"""
        self.completed = True
        self.completed_at = datetime.now(timezone.utc)
        self.points_earned = points or self.challenge.base_points
        self.bonus_earned = bonus
        self.success_method = method

        # Update user's total score
        self.user.total_score += self.points_earned + self.bonus_earned
        self.user.experience_points += self.points_earned

        # Update challenge statistics
        self.challenge.successful_attempts += 1

        db.session.commit()

    def record_attempt(self):
        """Record a new attempt"""
        self.attempts_count += 1
        self.last_attempt_at = datetime.now(timezone.utc)

        if self.first_attempt_at is None:
            self.first_attempt_at = self.last_attempt_at

        # Update challenge statistics
        self.challenge.total_attempts += 1

        db.session.commit()

    def use_hint(self):
        """Record hint usage"""
        if self.hints_used < self.challenge.hints_allowed:
            self.hints_used += 1
            db.session.commit()
            return True
        return False

    def get_completion_time(self):
        """Get time taken to complete challenge"""
        if self.completed_at and self.started_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds() / 60  # Return minutes
        return None

    def __repr__(self):
        return f"<UserChallenge {self.user.username}-{self.challenge.slug}>"


class Flag(db.Model):
    """Enhanced flag model with better tracking"""

    __tablename__ = "flags"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Flag details
    flag_value = db.Column(db.String(200), nullable=False, unique=True)
    flag_format = db.Column(db.String(50), default="R00T{...}")

    # Status
    is_used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)

    # Generation metadata
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)
    generation_method = db.Column(db.String(50), default="dynamic")

    # Constraints
    __table_args__ = (
        db.UniqueConstraint(
            "challenge_id", "user_id", name="unique_user_challenge_flag"
        ),
    )

    def mark_used(self):
        """Mark flag as used"""
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)
        db.session.commit()

    def is_expired(self):
        """Check if flag is expired"""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False

    def __repr__(self):
        return f"<Flag {self.challenge.slug}-{self.user.username}>"


class Submission(db.Model):
    """Enhanced submission model with detailed analytics"""

    __tablename__ = "submissions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)

    # Submission details
    submitted_flag = db.Column(db.String(200), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

    # Context information
    user_agent = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    submission_method = db.Column(db.String(50), default="web")  # web, api, cli

    # Analytics
    time_from_start = db.Column(db.Integer, nullable=True)  # seconds from first attempt
    confidence_level = db.Column(db.Integer, nullable=True)  # 1-10 user confidence

    # Timestamps
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Submission {self.user.username}-{self.challenge.slug}: {'✓' if self.is_correct else '✗'}>"


class Hint(db.Model):
    """Contextual hints for challenges"""

    __tablename__ = "hints"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)

    # Hint details
    hint_order = db.Column(db.Integer, nullable=False)  # 1, 2, 3...
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    hint_type = db.Column(db.String(50), default="text")  # text, code, image, video

    # Accessibility
    unlock_after_attempts = db.Column(db.Integer, default=0)
    points_cost = db.Column(db.Integer, default=0)  # Points deducted for hint

    # Content metadata
    difficulty_level = db.Column(db.Integer, default=1)  # 1=easy hint, 3=major spoiler
    tags = db.Column(db.JSON, default=list)  # e.g., ['tool', 'technique', 'concept']

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Constraints
    __table_args__ = (
        db.UniqueConstraint(
            "challenge_id", "hint_order", name="unique_challenge_hint_order"
        ),
    )

    def __repr__(self):
        return f"<Hint {self.challenge.slug}-{self.hint_order}: {self.title}>"


class Achievement(db.Model):
    """Achievement definitions"""

    __tablename__ = "achievements"

    id = db.Column(db.Integer, primary_key=True)

    # Basic information
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(50), nullable=True)

    # Achievement metadata
    category = db.Column(
        db.String(50), nullable=False
    )  # e.g., 'completion', 'speed', 'streak'
    difficulty = db.Column(db.Enum(DifficultyLevel), nullable=False)
    points_reward = db.Column(db.Integer, default=0)

    # Unlock conditions (JSON configuration)
    unlock_conditions = db.Column(db.JSON, nullable=False)

    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_hidden = db.Column(db.Boolean, default=False)  # Hidden until unlocked

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user_achievements = db.relationship(
        "UserAchievement", backref="achievement", lazy="dynamic"
    )

    def __repr__(self):
        return f"<Achievement {self.name}>"


class UserAchievement(db.Model):
    """User achievement unlocks"""

    __tablename__ = "user_achievements"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    achievement_id = db.Column(
        db.Integer, db.ForeignKey("achievements.id"), nullable=False
    )

    # Achievement details
    unlocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    progress_when_unlocked = db.Column(
        db.JSON, default=dict
    )  # Snapshot of user progress

    # Constraints
    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "achievement_id", name="unique_user_achievement"
        ),
    )

    def __repr__(self):
        return f"<UserAchievement {self.user.username}-{self.achievement.name}>"


class LearningPath(db.Model):
    """Structured learning paths for guided progression"""

    __tablename__ = "learning_paths"

    id = db.Column(db.Integer, primary_key=True)

    # Path information
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)

    # Path configuration
    difficulty = db.Column(db.Enum(DifficultyLevel), nullable=False)
    estimated_hours = db.Column(db.Integer, nullable=True)
    prerequisites = db.Column(db.JSON, default=list)  # Required skills/challenges

    # Challenge sequence
    challenge_sequence = db.Column(
        db.JSON, nullable=False
    )  # Ordered list of challenge IDs

    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user_paths = db.relationship(
        "UserLearningPath", backref="learning_path", lazy="dynamic"
    )

    def get_completion_rate(self):
        """Calculate average completion rate for this path"""
        total_users = self.user_paths.count()
        if total_users == 0:
            return 0

        completed_users = self.user_paths.filter_by(completed=True).count()
        return round((completed_users / total_users) * 100, 2)

    def __repr__(self):
        return f"<LearningPath {self.name}>"


class UserLearningPath(db.Model):
    """User progress on learning paths"""

    __tablename__ = "user_learning_paths"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    learning_path_id = db.Column(
        db.Integer, db.ForeignKey("learning_paths.id"), nullable=False
    )

    # Progress tracking
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    current_challenge_index = db.Column(db.Integer, default=0)

    # Analytics
    time_spent = db.Column(db.Integer, default=0)  # Total seconds spent
    challenges_completed = db.Column(db.Integer, default=0)

    # Constraints
    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "learning_path_id", name="unique_user_learning_path"
        ),
    )

    def get_progress_percentage(self):
        """Calculate progress percentage"""
        total_challenges = len(self.learning_path.challenge_sequence)
        if total_challenges == 0:
            return 100
        return round((self.challenges_completed / total_challenges) * 100, 2)

    def get_next_challenge(self):
        """Get next challenge in the path"""
        if self.current_challenge_index < len(self.learning_path.challenge_sequence):
            challenge_id = self.learning_path.challenge_sequence[
                self.current_challenge_index
            ]
            return Challenge.query.get(challenge_id)
        return None

    def advance_to_next_challenge(self):
        """Move to next challenge in sequence"""
        if (
            self.current_challenge_index
            < len(self.learning_path.challenge_sequence) - 1
        ):
            self.current_challenge_index += 1
            self.challenges_completed += 1

            # Check if path is completed
            if self.current_challenge_index >= len(
                self.learning_path.challenge_sequence
            ):
                self.completed = True
                self.completed_at = datetime.now(timezone.utc)

            db.session.commit()
            return True
        return False

    def __repr__(self):
        return f"<UserLearningPath {self.user.username}-{self.learning_path.slug}>"


# Import all models to ensure they're registered
__all__ = [
    "User",
    "Team",
    "Challenge",
    "UserChallenge",
    "Flag",
    "Submission",
    "Hint",
    "Achievement",
    "UserAchievement",
    "LearningPath",
    "UserLearningPath",
    "DifficultyLevel",
    "ChallengeCategory",
    "UserRole",
]
