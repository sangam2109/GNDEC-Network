from mongoengine import connect
import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Connect directly using PyMongo for the migration
client = MongoClient(os.getenv('MONGODB_URI'))
db = client.get_default_database()

def migrate_posts():
    try:
        # Get the posts collection
        posts = db.posts
        
        # Update all documents
        result = posts.update_many(
            {"like_ids": {"$exists": False}},  # Find posts without like_ids
            [
                {
                    "$set": {
                        "like_ids": [],  # Add empty like_ids array
                    }
                },
                {
                    "$unset": "likes"  # Remove old likes field
                }
            ]
        )
        
        print(f"Modified {result.modified_count} documents")
        print("Migration completed successfully!")
        
    except Exception as e:
        print(f"Error during migration: {str(e)}")
    finally:
        client.close()

if __name__ == "__main__":
    migrate_posts() 