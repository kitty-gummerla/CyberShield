"""
MongoDB Database Connection & Data Access Layer

Uses Motor (Async Python Driver) for non-blocking database I/O.
Handles CRUD operations for the `analyses` collection.
"""

import os
import logging
from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from bson import ObjectId
from datetime import datetime

logger = logging.getLogger(__name__)


class MongoDBManager:
    """Manages the MongoDB client connection and database operations."""

    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.is_connected: bool = False

    async def connect(self):
        """Initializes connection to MongoDB using MONGODB_URL from .env."""
        mongo_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        db_name = os.getenv("DATABASE_NAME", "phishing_detection_db")

        try:
            logger.info(f"Connecting to MongoDB at {mongo_url}...")
            self.client = AsyncIOMotorClient(
                mongo_url,
                serverSelectionTimeoutMS=3000  # 3-second timeout for quick fallback
            )
            # Ping database to verify connection
            await self.client.admin.command('ping')
            self.db = self.client[db_name]
            self.is_connected = True
            logger.info(f"✅ Successfully connected to MongoDB database: '{db_name}'")
        except Exception as e:
            self.is_connected = False
            logger.warning(
                f"⚠️ MongoDB connection failed ({str(e)}). "
                "The app will continue running, but history persistence will be disabled."
            )

    async def disconnect(self):
        """Closes the MongoDB connection pool."""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB connection closed.")

    # ─────────────────────────────────────────────
    # CRUD OPERATIONS: analyses COLLECTION
    # ─────────────────────────────────────────────

    async def save_analysis(self, analysis_dict: Dict[str, Any]) -> Optional[str]:
        """
        Inserts a completed email analysis document into MongoDB.
        Returns the string representation of the inserted _id.
        """
        if not self.is_connected or self.db is None:
            logger.warning("MongoDB is offline. Skipping database persistence.")
            return None

        try:
            # Ensure timestamp is recorded
            if "analyzed_at" not in analysis_dict or not analysis_dict["analyzed_at"]:
                analysis_dict["analyzed_at"] = datetime.utcnow()

            result = await self.db.analyses.insert_one(analysis_dict)
            inserted_id = str(result.inserted_id)
            logger.info(f"Analysis saved to MongoDB with ID: {inserted_id}")
            return inserted_id
        except Exception as e:
            logger.error(f"Failed to save analysis to MongoDB: {e}")
            return None

    async def get_analyses(self, limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieves a paginated list of past email analyses, sorted newest first.
        """
        if not self.is_connected or self.db is None:
            return []

        try:
            cursor = self.db.analyses.find().sort("analyzed_at", -1).skip(skip).limit(limit)
            records = []
            async for doc in cursor:
                doc["analysis_id"] = str(doc["_id"])
                doc["_id"] = str(doc["_id"])
                records.append(doc)
            return records
        except Exception as e:
            logger.error(f"Failed to fetch analyses from MongoDB: {e}")
            return []

    async def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches a single analysis document by its string ID.
        """
        if not self.is_connected or self.db is None:
            return None

        try:
            if not ObjectId.is_valid(analysis_id):
                return None

            doc = await self.db.analyses.find_one({"_id": ObjectId(analysis_id)})
            if doc:
                doc["analysis_id"] = str(doc["_id"])
                doc["_id"] = str(doc["_id"])
                return doc
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
            return None

    async def delete_analysis_by_id(self, analysis_id: str) -> bool:
        """
        Deletes an analysis record by its ID.
        """
        if not self.is_connected or self.db is None:
            return False

        try:
            if not ObjectId.is_valid(analysis_id):
                return False

            result = await self.db.analyses.delete_one({"_id": ObjectId(analysis_id)})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete analysis {analysis_id}: {e}")
            return False
    # ─────────────────────────────────────────────
    # CRUD OPERATIONS: remediations COLLECTION
    # ─────────────────────────────────────────────

    async def save_remediation(self, remediation_dict: Dict[str, Any]) -> Optional[str]:
        """
        Inserts a completed remediation execution record into MongoDB.
        Returns the string representation of the inserted _id.
        """
        if not self.is_connected or self.db is None:
            logger.warning("MongoDB is offline. Skipping remediation persistence.")
            return None

        try:
            if "executed_at" not in remediation_dict or not remediation_dict["executed_at"]:
                remediation_dict["executed_at"] = datetime.utcnow()

            result = await self.db.remediations.insert_one(remediation_dict)
            inserted_id = str(result.inserted_id)
            logger.info(f"Remediation record saved to MongoDB with ID: {inserted_id}")
            return inserted_id
        except Exception as e:
            logger.error(f"Failed to save remediation to MongoDB: {e}")
            return None

    async def get_remediations(self, limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieves a paginated list of past remediation records, sorted newest first.
        """
        if not self.is_connected or self.db is None:
            return []

        try:
            cursor = self.db.remediations.find().sort("executed_at", -1).skip(skip).limit(limit)
            records = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                records.append(doc)
            return records
        except Exception as e:
            logger.error(f"Failed to fetch remediations from MongoDB: {e}")
            return []

    async def get_remediation_by_id(self, remediation_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches a single remediation document by its remediation_id field.
        """
        if not self.is_connected or self.db is None:
            return None

        try:
            doc = await self.db.remediations.find_one({"remediation_id": remediation_id})
            if doc:
                doc["_id"] = str(doc["_id"])
                return doc
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve remediation {remediation_id}: {e}")
            return None

# ═══════════════════════════════════════════════════════════════════
# Global Database Instance
# ═══════════════════════════════════════════════════════════════════
db_manager = MongoDBManager()