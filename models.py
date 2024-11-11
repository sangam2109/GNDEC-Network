from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

class User(UserMixin, db.Model):
    # ... existing fields ...
    
    def is_friend(self, user):
        """Check if the given user is a friend"""
        return self.friends.filter_by(id=user.id).first() is not None

    def has_sent_friend_request(self, user):
        """Check if a friend request has been sent to the user"""
        return FriendRequest.query.filter_by(
            sender_id=self.id,
            receiver_id=user.id,
            status='pending'
        ).first() is not None

    def get_friend_request(self, user):
        """Get the friend request between self and user"""
        return FriendRequest.query.filter_by(
            sender_id=user.id,
            receiver_id=self.id,
            status='pending'
        ).first()

    @property
    def received_friend_requests(self):
        """Get all pending friend requests received by the user"""
        return FriendRequest.query.filter_by(
            receiver_id=self.id,
            status='pending'
        ).all() 