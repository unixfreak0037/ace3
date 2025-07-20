import logging
import os
import shutil
from typing import Optional

from saq.analysis.root import RootAnalysis, Submission
from saq.util import create_directory


class SubmissionFileManager:
    """Handles all file system operations for submissions."""
    
    def __init__(self, incoming_dir: str, persistence_dir: str):
        """
        Initialize the SubmissionFileManager.
        
        Args:
            incoming_dir: Directory where submission files are stored for processing
            persistence_dir: Directory for persistence data storage
        """
        self.incoming_dir = incoming_dir
        self.persistence_dir = persistence_dir
    
    def initialize_directories(self):
        """Create required directories if they don't exist."""
        for dir_path in [self.incoming_dir, self.persistence_dir]:
            create_directory(dir_path)
    
    def prepare_submission_files(self, submission: Submission):
        """
        Prepare submission files by saving the root and moving it to the incoming directory.
        
        Args:
            submission: The Submission object to prepare
        """
        assert isinstance(submission, Submission)
        assert isinstance(submission.root, RootAnalysis)
        
        # Save the root and move it into the incoming dir
        submission.root.save()
        target_dir = os.path.join(self.incoming_dir, submission.root.uuid)
        submission.root.move(target_dir)
    
    def delete_submission_directory(self, root_uuid: str) -> bool:
        """
        Delete the submission directory for a completed workload.
        
        Args:
            root_uuid: The UUID of the root analysis to delete
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        target_dir = os.path.join(self.incoming_dir, root_uuid)
        
        try:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
                return True
            return True  # Directory doesn't exist, consider it successful
        except Exception as e:
            logging.error("unable to delete incoming workload directory %s: %s", target_dir, e)
            return False
    
    def get_submission_directory_path(self, root_uuid: str) -> str:
        """
        Get the path to a submission's directory.
        
        Args:
            root_uuid: The UUID of the root analysis
            
        Returns:
            str: The full path to the submission directory
        """
        return os.path.join(self.incoming_dir, root_uuid)
    
    def submission_directory_exists(self, root_uuid: str) -> bool:
        """
        Check if a submission directory exists.
        
        Args:
            root_uuid: The UUID of the root analysis
            
        Returns:
            bool: True if the directory exists, False otherwise
        """
        target_dir = os.path.join(self.incoming_dir, root_uuid)
        return os.path.exists(target_dir) 