#!/usr/bin/env python3
"""
Browser History and Artifact Extraction
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Extracts forensic artifacts from web browsers including:
    - Browsing history
    - Download history
    - Cookies
    - Autofill data
    - Bookmarks
    Supports: Chrome, Edge, Firefox, Safari

Requirements:
    - Python 3.8+
    - sqlite3 (built-in)

Usage:
    python extract-browser-history.py --user-profile C:\\Users\\John --output browser_artifacts/
    python extract-browser-history.py --browser chrome --output artifacts/
    python extract-browser-history.py --offline E:\\evidence\\Users\\John --output analysis/
"""

import argparse
import json
import logging
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class BrowserForensics:
    """Extract forensic artifacts from web browsers"""

    def __init__(self, user_profile: Path, output_dir: Path):
        self.user_profile = user_profile
        self.output_dir = output_dir
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "user_profile": str(user_profile),
            "browsers_analyzed": [],
            "artifacts_extracted": {},
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def chrome_timestamp_to_datetime(self, chrome_timestamp: int) -> str:
        """
        Convert Chrome timestamp to readable datetime

        Args:
            chrome_timestamp: Chrome timestamp (microseconds since 1601-01-01)

        Returns:
            ISO format datetime string
        """
        try:
            # Chrome uses microseconds since 1601-01-01
            epoch_start = datetime(1601, 1, 1)
            delta = timedelta(microseconds=chrome_timestamp)
            return (epoch_start + delta).isoformat()
        except:
            return "Invalid timestamp"

    def firefox_timestamp_to_datetime(self, firefox_timestamp: int) -> str:
        """
        Convert Firefox timestamp to readable datetime

        Args:
            firefox_timestamp: Firefox timestamp (microseconds since epoch)

        Returns:
            ISO format datetime string
        """
        try:
            return datetime.fromtimestamp(firefox_timestamp / 1000000).isoformat()
        except:
            return "Invalid timestamp"

    def extract_chrome_history(self) -> bool:
        """
        Extract Chrome browsing history

        Returns:
            bool: True if successful
        """
        logger.info("[+] Extracting Chrome history...")

        chrome_paths = [
            self.user_profile / "AppData/Local/Google/Chrome/User Data/Default",
            self.user_profile / "Local Settings/Application Data/Google/Chrome/User Data/Default",
        ]

        for chrome_path in chrome_paths:
            history_db = chrome_path / "History"

            if not history_db.exists():
                continue

            try:
                # Copy database to avoid locks
                temp_db = self.output_dir / "chrome_history_temp.db"
                shutil.copy2(history_db, temp_db)

                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                # Extract browsing history
                cursor.execute(
                    """
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                """
                )

                history = []
                for row in cursor.fetchall():
                    history.append(
                        {
                            "url": row[0],
                            "title": row[1],
                            "visit_count": row[2],
                            "last_visit": self.chrome_timestamp_to_datetime(row[3]),
                        }
                    )

                # Extract downloads
                cursor.execute(
                    """
                    SELECT target_path, tab_url, start_time, end_time, total_bytes
                    FROM downloads
                    ORDER BY start_time DESC
                """
                )

                downloads = []
                for row in cursor.fetchall():
                    downloads.append(
                        {
                            "file": row[0],
                            "url": row[1],
                            "start_time": self.chrome_timestamp_to_datetime(row[2]),
                            "end_time": self.chrome_timestamp_to_datetime(row[3]),
                            "size_bytes": row[4],
                        }
                    )

                conn.close()
                temp_db.unlink()

                # Save results
                output_file = self.output_dir / "chrome_history.json"
                with open(output_file, "w") as f:
                    json.dump({"browsing_history": history, "downloads": downloads}, f, indent=2)

                self.results["artifacts_extracted"]["chrome_history"] = len(history)
                self.results["artifacts_extracted"]["chrome_downloads"] = len(downloads)
                self.results["browsers_analyzed"].append("Chrome")

                logger.info(f"[OK] Chrome: {len(history)} URLs, {len(downloads)} downloads")
                return True

            except Exception as e:
                logger.error(f"[X] Error extracting Chrome history: {e}")
                return False

        logger.warning("[!] Chrome history database not found")
        return False

    def extract_edge_history(self) -> bool:
        """
        Extract Edge browsing history

        Returns:
            bool: True if successful
        """
        logger.info("[+] Extracting Edge history...")

        edge_paths = [
            self.user_profile / "AppData/Local/Microsoft/Edge/User Data/Default",
        ]

        for edge_path in edge_paths:
            history_db = edge_path / "History"

            if not history_db.exists():
                continue

            try:
                # Copy database
                temp_db = self.output_dir / "edge_history_temp.db"
                shutil.copy2(history_db, temp_db)

                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                # Extract history (same schema as Chrome)
                cursor.execute(
                    """
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                """
                )

                history = []
                for row in cursor.fetchall():
                    history.append(
                        {
                            "url": row[0],
                            "title": row[1],
                            "visit_count": row[2],
                            "last_visit": self.chrome_timestamp_to_datetime(row[3]),
                        }
                    )

                conn.close()
                temp_db.unlink()

                # Save results
                output_file = self.output_dir / "edge_history.json"
                with open(output_file, "w") as f:
                    json.dump({"browsing_history": history}, f, indent=2)

                self.results["artifacts_extracted"]["edge_history"] = len(history)
                self.results["browsers_analyzed"].append("Edge")

                logger.info(f"[OK] Edge: {len(history)} URLs")
                return True

            except Exception as e:
                logger.error(f"[X] Error extracting Edge history: {e}")
                return False

        logger.warning("[!] Edge history database not found")
        return False

    def extract_firefox_history(self) -> bool:
        """
        Extract Firefox browsing history

        Returns:
            bool: True if successful
        """
        logger.info("[+] Extracting Firefox history...")

        firefox_profiles = self.user_profile / "AppData/Roaming/Mozilla/Firefox/Profiles"

        if not firefox_profiles.exists():
            logger.warning("[!] Firefox profiles directory not found")
            return False

        for profile_dir in firefox_profiles.iterdir():
            if not profile_dir.is_dir():
                continue

            places_db = profile_dir / "places.sqlite"
            if not places_db.exists():
                continue

            try:
                # Copy database
                temp_db = self.output_dir / "firefox_places_temp.db"
                shutil.copy2(places_db, temp_db)

                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                # Extract history
                cursor.execute(
                    """
                    SELECT url, title, visit_count, last_visit_date
                    FROM moz_places
                    WHERE last_visit_date IS NOT NULL
                    ORDER BY last_visit_date DESC
                """
                )

                history = []
                for row in cursor.fetchall():
                    history.append(
                        {
                            "url": row[0],
                            "title": row[1],
                            "visit_count": row[2],
                            "last_visit": self.firefox_timestamp_to_datetime(row[3]),
                        }
                    )

                # Extract downloads
                cursor.execute(
                    """
                    SELECT content, dateAdded
                    FROM moz_anno_attributes
                    JOIN moz_annos ON moz_anno_attributes.id = moz_annos.anno_attribute_id
                    WHERE moz_anno_attributes.name = 'downloads/destinationFileName'
                """
                )

                downloads = []
                for row in cursor.fetchall():
                    downloads.append(
                        {"file": row[0], "date": self.firefox_timestamp_to_datetime(row[1])}
                    )

                conn.close()
                temp_db.unlink()

                # Save results
                output_file = self.output_dir / "firefox_history.json"
                with open(output_file, "w") as f:
                    json.dump(
                        {
                            "profile": profile_dir.name,
                            "browsing_history": history,
                            "downloads": downloads,
                        },
                        f,
                        indent=2,
                    )

                self.results["artifacts_extracted"]["firefox_history"] = len(history)
                self.results["artifacts_extracted"]["firefox_downloads"] = len(downloads)
                self.results["browsers_analyzed"].append("Firefox")

                logger.info(f"[OK] Firefox: {len(history)} URLs, {len(downloads)} downloads")
                return True

            except Exception as e:
                logger.error(f"[X] Error extracting Firefox history: {e}")
                return False

        return False

    def extract_chrome_cookies(self) -> bool:
        """
        Extract Chrome cookies

        Returns:
            bool: True if successful
        """
        logger.info("[+] Extracting Chrome cookies...")

        chrome_path = self.user_profile / "AppData/Local/Google/Chrome/User Data/Default"
        cookies_db = chrome_path / "Cookies"

        if not cookies_db.exists():
            logger.warning("[!] Chrome cookies database not found")
            return False

        try:
            temp_db = self.output_dir / "chrome_cookies_temp.db"
            shutil.copy2(cookies_db, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT host_key, name, path, creation_utc, last_access_utc, expires_utc, is_secure
                FROM cookies
            """
            )

            cookies = []
            for row in cursor.fetchall():
                cookies.append(
                    {
                        "domain": row[0],
                        "name": row[1],
                        "path": row[2],
                        "created": self.chrome_timestamp_to_datetime(row[3]),
                        "last_access": self.chrome_timestamp_to_datetime(row[4]),
                        "expires": self.chrome_timestamp_to_datetime(row[5]),
                        "secure": bool(row[6]),
                    }
                )

            conn.close()
            temp_db.unlink()

            # Save results
            output_file = self.output_dir / "chrome_cookies.json"
            with open(output_file, "w") as f:
                json.dump({"cookies": cookies}, f, indent=2)

            self.results["artifacts_extracted"]["chrome_cookies"] = len(cookies)
            logger.info(f"[OK] Chrome: {len(cookies)} cookies")
            return True

        except Exception as e:
            logger.error(f"[X] Error extracting Chrome cookies: {e}")
            return False

    def generate_report(self) -> None:
        """Generate extraction report"""
        logger.info("\n" + "=" * 70)
        logger.info("Browser Forensics Report")
        logger.info("=" * 70)

        logger.info(f"\nUser Profile: {self.user_profile}")
        logger.info(f"Output Directory: {self.output_dir}")
        logger.info(f"Timestamp: {self.results['timestamp']}")

        logger.info(
            f"\n[+] Browsers Analyzed: {', '.join(self.results['browsers_analyzed']) or 'None'}"
        )

        if self.results["artifacts_extracted"]:
            logger.info("\n[+] Artifacts Extracted:")
            for artifact, count in self.results["artifacts_extracted"].items():
                logger.info(f"  {artifact}: {count}")
        else:
            logger.info("\n[!] No artifacts extracted")

        # Save report
        report_file = self.output_dir / "browser_forensics_report.json"
        with open(report_file, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"\n[OK] Report saved to: {report_file}")
        logger.info("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Browser forensics artifact extraction")
    parser.add_argument(
        "--user-profile",
        type=Path,
        required=True,
        help="User profile directory (e.g., C:\\Users\\John)",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("browser_artifacts"), help="Output directory"
    )
    parser.add_argument(
        "--browser",
        choices=["chrome", "edge", "firefox", "all"],
        default="all",
        help="Browser to extract from",
    )

    args = parser.parse_args()

    if not args.user_profile.exists():
        logger.error(f"[X] User profile not found: {args.user_profile}")
        return 1

    forensics = BrowserForensics(args.user_profile, args.output)

    # Extract artifacts based on browser selection
    extracted_any = False

    if args.browser in ["chrome", "all"]:
        if forensics.extract_chrome_history():
            extracted_any = True
        forensics.extract_chrome_cookies()

    if args.browser in ["edge", "all"]:
        if forensics.extract_edge_history():
            extracted_any = True

    if args.browser in ["firefox", "all"]:
        if forensics.extract_firefox_history():
            extracted_any = True

    # Generate report
    forensics.generate_report()

    return 0 if extracted_any else 1


if __name__ == "__main__":
    exit(main())
