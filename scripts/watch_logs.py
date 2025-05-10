import psycopg2
import os
import csv
import sys
import time
import logging
import argparse
from datetime import datetime, timezone, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from psycopg2 import OperationalError, ProgrammingError, extras # Import extras for batching

# --- Configuration ---

# Database Connection (from previous script)
DB_PARAMS = {
    "database": "",
    "user": "",
    "password": "",
    "host": "",
    "port": ""
}

# Directory containing the Zeek log files to monitor
LOG_DIR_TO_WATCH = "/opt/zeek/logs/current/" # !!! IMPORTANT: CHANGE THIS PATH !!!

# Mapping from Zeek log filenames to database table names and expected columns
# IMPORTANT: The order of columns MUST match the order in your CREATE TABLE statements
#            AND the order of fields in the Zeek log's #fields header.
#            This example assumes the column order from the previous script.
#            A more robust solution would parse the #fields header dynamically.
LOG_FILE_CONFIG = {
    "conn.log": {
        "table_name": "conn_log",
        "columns": [
            "time","ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
            "ip_proto"
        ]
    },
    "http.log": {
        "table_name": "http_log",
        "columns": [
            "time","ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "trans_depth", "method", "host", "uri", "referrer", "version",
            "user_agent", "origin", "request_body_len", "response_body_len",
            "status_code", "status_msg", "info_code", "info_msg", "tags",
            "username", "password", "proxied", "orig_fuids", "orig_filenames", "orig_mime_types",
            "resp_fuids", "resp_filenames", "resp_mime_types"
        ]
    },
    "dns.log": {
        "table_name": "dns_log",
        "columns": [
            "time","ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
            "qtype", "qtype_name", "rcode", "rcode_name", "aa", "tc", "rd",
            "ra", "z", "answers", "ttls", "rejected"
        ]
    },
    "ssh.log": {
        "table_name": "ssh_log",
        "columns": [
            "time",
            "ts",
            "uid",
            "id_orig_h",
            "id_orig_p",
            "id_resp_h",
            "id_resp_p",
            "version",
            "auth_success",
            "auth_attempts",
            "direction",
            "client",
            "server",
            "cipher_alg",
            "mac_alg",
            "compression_alg",
            "kex_alg",
            "host_key_alg",
            "host_key",
            "remote_location_country_code",
            "remote_location_region",
            "remote_location_city",
            "remote_location_latitude",
            "remote_location_longitude"
        ]
    },
    "files.log": {
        "table_name": "files_log",
        "columns": [
            "time","ts",
            "fuid",
            "uid",
            "id_orig_h",
            "id_orig_p",
            "id_resp_h",
            "id_resp_p",
            "source",
            "depth",
            "analyzers",
            "mime_type",
            "filename",
            "duration",
            "local_orig",
            "is_orig",
            "seen_bytes",
            "total_bytes",
            "missing_bytes",
            "overflow_bytes",
            "timedout",
            "parent_fuid",
            "md5",
            "sha1",
            "sha256",
            "extracted",
            "extracted_cutoff",
            "extracted_size" 
        ]
    },
    "analyzer.log": {
        "table_name": "analyzer_log",
        "columns": [
            "time",
            "ts",
            "cause",
            "analyzer_kind",
            "analyzer_name",
            "uid",
            "fuid",
            "id_orig_h",
            "id_orig_p",
            "id_resp_h",
            "id_resp_p",
            "failure_reason",
            "failure_data"
        ]
    },
    "telemetry.log": {
        "table_name": "telemetry_log",
        "columns": [
            "time",
            "ts",
            "peer",
            "metric_type",
            "name",
            "labels",
            "label_values",
            "value"
        ]
    },
    # --- Add other log file mappings here (e.g., files.log, ssl.log) ---
}

# How many rows to batch before inserting
INSERT_BATCH_SIZE = 100

# How often to check for inserting remaining rows if batch size not reached (seconds)
BATCH_TIMEOUT = 5.0

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# --- State Variables ---
# Dictionary to store the last read position (byte offset) for each file
file_positions = {}
# Dictionary to store pending rows for batch insertion { table_name: [row_tuple, ...] }
pending_rows = {config["table_name"]: [] for config in LOG_FILE_CONFIG.values()}
# Timestamp of the last batch insert check
last_batch_check_time = time.time()

# --- Helper Functions ---

def zeek_timestamp_to_pg(zeek_ts_str):
    """Converts Zeek epoch timestamp string to Python datetime object (UTC)."""
    try:
        # Zeek timestamp is epoch float
        timestamp = float(zeek_ts_str)
        # Convert to timezone-aware datetime object in UTC
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (ValueError, TypeError) as e:
        logging.warning(f"Could not parse timestamp '{zeek_ts_str}': {e}. Returning None.")
        return None # Or raise an error, or return a default?

def parse_zeek_value(value_str, column_name, expected_type):
    """Attempts to parse Zeek string value based on expected column type."""
    if value_str == '-' or value_str == '(empty)': # Common Zeek placeholders for null/empty
        return None

    # Basic type guessing - A more robust solution might map column names to types explicitly
    if expected_type in ('integer', 'bigint'):
        try: return int(value_str)
        except ValueError: return None
    elif expected_type in ('double precision', 'float'):
        try: return float(value_str)
        except ValueError: return None
    elif expected_type == 'boolean':
        return value_str.upper() == 'T' # Zeek uses T/F for boolean
    elif expected_type == 'timestamp with time zone':
         # Handled separately by zeek_timestamp_to_pg based on column name 'ts'
         return value_str # Keep as string for now, will be converted later
    elif expected_type == 'inet':
        # psycopg2 handles string IP addresses directly
        return value_str
    else: # text, varchar, etc.
        # Zeek TSV decoding might be needed for escaped characters if not handled by csv
        return value_str

def get_db_connection():
    """Establishes and returns a new database connection."""
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        logging.debug(f"Successfully connected to database '{DB_PARAMS['database']}'.")
        return conn
    except OperationalError as e:
        logging.error(f"Could not connect to database '{DB_PARAMS['database']}': {e}")
        return None

def insert_batch(conn, table_name, rows):
    """Inserts a batch, duplicating the converted 'ts' value into the 'time' column."""
    if not rows:
        return True # Nothing to insert

    # --- Get Configuration ---
    config = next((c for file, c in LOG_FILE_CONFIG.items() if c["table_name"] == table_name), None)
    if not config:
        logging.error(f"No configuration found for table '{table_name}'. Skipping insert.")
        return False

    num_columns_db = len(config["columns"]) # Total columns in DB table (including 'time')
    num_columns_log_expected = num_columns_db - 1 # Log file has one less column than DB

    column_names_str = ", ".join(f'"{col}"' for col in config["columns"])
    placeholders = ", ".join(["%s"] * num_columns_db)
    sql = f"INSERT INTO {table_name} ({column_names_str}) VALUES ({placeholders})"

    # Check if the table has a known primary key to add ON CONFLICT clause
    # (Adapt this if your primary keys differ between tables)
    if table_name in ["http_log", "conn_log", "dns_log"]: # Add other tables with (ts, uid) pkey
        # Assumes the primary key is (ts, uid) for these tables
        # Adjust the column names if your primary key is different!
        sql += " ON CONFLICT (ts, uid) DO NOTHING"
    # Optional: Add ON CONFLICT clause if needed, e.g.:
    #sql += " ON CONFLICT (ts, uid) DO NOTHING" # Adjust conflict target columns

    cursor = None
    prepared_rows = [] # Store rows ready for DB insertion

    try:
        # --- Find Indices for 'ts' and 'time' ---
        try:
            ts_db_idx = config["columns"].index("ts")
            time_db_idx = config["columns"].index("time")
            logging.debug(f"Config for {table_name}: 'ts' index={ts_db_idx}, 'time' index={time_db_idx}")
        except ValueError as e:
            logging.error(f"Configuration Error for table '{table_name}': Column 'ts' or 'time' missing in config['columns']. {e}")
            return False # Cannot proceed

        # --- Prepare Rows ---
        for row_tuple_from_log in rows:
            # Verify input row length
            if len(row_tuple_from_log) != num_columns_log_expected:
                logging.warning(f"Input row length mismatch for {table_name}, expected {num_columns_log_expected} log fields, got {len(row_tuple_from_log)}. Skipping row: {row_tuple_from_log}")
                continue

            # Create placeholder list for the final DB row
            final_db_row = [None] * num_columns_db
            valid_row = True

            # 1. Process Timestamp (Assume it's the FIRST field in the log row)
            original_ts_str = row_tuple_from_log[0]
            ts_datetime_obj = zeek_timestamp_to_pg(original_ts_str)

            if ts_datetime_obj is None:
                logging.warning(f"Skipping row due to invalid timestamp '{original_ts_str}' in {table_name}. Row: {row_tuple_from_log}")
                continue # Skip this row

            # Assign the SAME converted timestamp object to BOTH positions
            final_db_row[ts_db_idx] = ts_datetime_obj
            final_db_row[time_db_idx] = ts_datetime_obj # <-- Key change: Duplicate the value

            # 2. Process Remaining Fields from the log
            log_field_idx = 1 # Start from the second field in the log tuple
            for db_col_idx in range(num_columns_db):
                # Skip the timestamp slots we already filled
                if db_col_idx == ts_db_idx or db_col_idx == time_db_idx:
                    continue

                # Check bounds (should be safe due to initial length check)
                if log_field_idx >= len(row_tuple_from_log):
                     logging.error(f"Logic error mapping log fields to DB columns for {table_name}. Row: {row_tuple_from_log}")
                     valid_row = False
                     break # Stop processing this row

                # Get value from log row and corresponding DB column name
                value = row_tuple_from_log[log_field_idx]
                col_name = config["columns"][db_col_idx]
                processed_value = value # Start with original

                # Apply standard cleaning (NULLs, Booleans)
                if isinstance(value, str) and (value == '-' or value == '(empty)'):
                    processed_value = None
                else:
                    # Handle Booleans ('T'/'F') - adapt set if needed
                    boolean_columns = {'aa', 'tc', 'rd', 'ra', 'rejected', 'local_orig', 'local_resp'}
                    if col_name in boolean_columns and isinstance(value, str) and value in ('T', 'F'):
                        processed_value = (value == 'T')
                    # Add other specific type conversions here if necessary

                final_db_row[db_col_idx] = processed_value
                log_field_idx += 1 # Move to the next field in the log row tuple

            # Add the fully constructed row to our batch if valid
            if valid_row:
                prepared_rows.append(tuple(final_db_row))

        # --- Execute Batch ---
        if not prepared_rows:
             logging.debug(f"No valid rows to insert into {table_name} after preparation.")
             return True # No valid rows left

        cursor = conn.cursor()
        logging.debug(f"Executing batch insert for {len(prepared_rows)} rows into {table_name}...")
        extras.execute_batch(cursor, sql, prepared_rows, page_size=len(prepared_rows))
        conn.commit()
        logging.info(f"Successfully inserted batch of {len(prepared_rows)} rows into {table_name}.")
        return True

    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f"Error inserting batch into {table_name}: {error}")
        # Enhanced logging for failed SQL example
        if prepared_rows and cursor:
             try:
                 if not cursor.closed:
                    # Use mogrify on the first row that would have been inserted
                    failed_sql_example = cursor.mogrify(sql, prepared_rows[0])
                    logging.error(f"Failed SQL Example (first row): {failed_sql_example.decode('utf-8', errors='replace')}")
                 else:
                     logging.error("Failed SQL Example: Cursor was closed.")
             except Exception as mogrify_error:
                 logging.error(f"Failed SQL Example: Error during mogrify: {mogrify_error}")
        else:
             # Log the generic SQL if no prepared rows available or cursor failed
             logging.error(f"Failed SQL Template: {sql}")

        logging.error(f"First few prepared rows data (up to 5): {prepared_rows[:5]}")
        if conn: conn.rollback()
        return False # Indicate failure
    finally:
        if cursor: cursor.close()

def process_log_file(filepath):
    """Reads new data from a log file, parses it, and adds to the pending batch."""
    global last_batch_check_time
    filename = os.path.basename(filepath)

    if filename not in LOG_FILE_CONFIG:
        logging.debug(f"Ignoring file {filename} as it's not in LOG_FILE_CONFIG.")
        return

    config = LOG_FILE_CONFIG[filename]
    table_name = config["table_name"]
    expected_columns = config["columns"]
    num_expected_columns = len(expected_columns)

    try:
        # Get current size and last known position
        current_size = os.path.getsize(filepath)
        last_pos = file_positions.get(filepath, 0)

        if current_size == last_pos:
            logging.debug(f"No change detected in {filename}.")
            return # No new data
        elif current_size < last_pos:
            logging.warning(f"File {filename} truncated or replaced? Resetting position.")
            last_pos = 0 # Reset position if file shrank

        logging.debug(f"Processing new data in {filename} from offset {last_pos} to {current_size}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(last_pos)
            new_content = f.read(current_size - last_pos)
            # Update position *after* successful read
            file_positions[filepath] = current_size

            # Process lines using csv reader
            # Use io.StringIO to treat the string content as a file
            #reader = csv.reader(io.StringIO(new_content), delimiter='\t') # <-- Original incorrect placement
            lines = new_content.strip().splitlines()
            if not lines:
                 logging.debug(f"No complete new lines found in {filename} segment.")
                 return

            reader = csv.reader(lines, delimiter='\t', quotechar=None) # Process extracted lines

            rows_added_to_batch = 0
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue # Skip empty lines and Zeek comments/headers

                if len(row) != num_expected_columns - 1:
                    logging.warning(f"Column count mismatch in {filename}. Expected {num_expected_columns}, got {len(row)}. Row: {row}")
                    continue # Skip rows with incorrect column count

                # Basic parsing/cleaning (can be expanded based on types)
                # parsed_row = [parse_zeek_value(val, col_name) for val, col_name in zip(row, expected_columns)]
                # For now, pass raw strings (except timestamp handled in insert_batch)
                pending_rows[table_name].append(tuple(row)) # Add as tuple
                rows_added_to_batch += 1

            if rows_added_to_batch > 0:
                 logging.debug(f"Added {rows_added_to_batch} rows from {filename} to batch for table {table_name}.")


    except FileNotFoundError:
        logging.warning(f"File {filepath} not found during processing (maybe deleted?). Removing from tracking.")
        if filepath in file_positions:
            del file_positions[filepath]
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}", exc_info=True)

    # Check if batches should be inserted (size or timeout)
    check_and_insert_batches(force_insert=False)


def check_and_insert_batches(force_insert=False):
    """Checks batch sizes and timeout, inserts if criteria met."""
    global last_batch_check_time
    now = time.time()
    time_elapsed = now - last_batch_check_time

    conn = None # Get connection only if needed

    for table_name, rows in list(pending_rows.items()): # Iterate over copy
        should_insert = False
        if force_insert and rows:
            should_insert = True
            logging.info(f"Forcing insert for remaining {len(rows)} rows in table {table_name}.")
        elif len(rows) >= INSERT_BATCH_SIZE:
            should_insert = True
            logging.info(f"Batch size reached for {table_name} ({len(rows)} rows). Inserting.")
        elif rows and time_elapsed >= BATCH_TIMEOUT:
            should_insert = True
            logging.info(f"Batch timeout reached for {table_name} ({len(rows)} rows). Inserting.")

        if should_insert:
            if conn is None: # Get connection only once if any batch needs insertion
                conn = get_db_connection()
                if conn is None:
                    logging.error("Cannot insert batches: No database connection.")
                    # Keep rows in pending_rows, maybe connection recovers later
                    return # Stop trying to insert for this cycle

            if insert_batch(conn, table_name, rows):
                # Clear the batch *only* on successful insert
                 pending_rows[table_name] = []
            else:
                 logging.warning(f"Batch insert failed for {table_name}. Rows remain pending.")
                 # Consider adding retry logic or dead-letter queue here

    # Close connection if it was opened
    if conn:
        conn.close()
        logging.debug("Database connection closed after batch check.")

    # Reset timer only if a check was actually performed (batches processed or timeout reached)
    if any(len(rows) >= INSERT_BATCH_SIZE for rows in pending_rows.values()) or time_elapsed >= BATCH_TIMEOUT:
        last_batch_check_time = now


# --- Watchdog Event Handler ---

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for Zeek log files."""

    def __init__(self, file_positions):
        self.file_positions = file_positions # Use the global state

    def on_modified(self, event):
        """Called when a file or directory is modified."""
        if event.is_directory:
            return # Ignore directory changes

        filepath = event.src_path
        filename = os.path.basename(filepath)

        if filename in LOG_FILE_CONFIG:
            logging.debug(f"Modification detected: {filepath}")
            process_log_file(filepath)
        # else:
            # logging.debug(f"Ignoring modification for non-log file: {filepath}")

    def on_created(self, event):
        """Called when a file or directory is created."""
        if event.is_directory:
            return

        filepath = event.src_path
        filename = os.path.basename(filepath)

        if filename in LOG_FILE_CONFIG:
            logging.info(f"New log file detected: {filepath}. Initializing position.")
            # Initialize position to 0 for new files
            self.file_positions[filepath] = 0
            # Optionally process immediately if it might already have content
            process_log_file(filepath)

def parse_db_params(args):
    """
    Parses database parameters from command-line arguments.

    Args:
        args (list): A list of command-line arguments.

    Returns:
        dict: A dictionary containing the database parameters.
    """
    parser = argparse.ArgumentParser(description="Parse database parameters.")
    parser.add_argument("--host", type=str, help="Database host", default="localhost")
    parser.add_argument("--port", type=int, help="Database port", default=5432)
    parser.add_argument("--user", type=str, help="Database user", default="postgres")
    parser.add_argument("--password", dest="password", help="Database password uses pipe to read from stdin")
    parser.add_argument("--database", type=str, help="Database name", default="postgres")

    arguments = parser.parse_args()
    password = arguments.password

    if not password:
        password = sys.stdin.readline().strip()  # Read password from stdin

    parsed_args = parser.parse_args(args)

    db_params = {
        "host": parsed_args.host,
        "port": parsed_args.port,
        "user": parsed_args.user,
        "password": password,
        "database": parsed_args.database,
    }

    return db_params


# --- Main Execution ---

if __name__ == "__main__":

    if len(sys.argv) > 1:
        try:
            DB_PARAMS = parse_db_params(sys.argv[1:])
            logging.info("Database parameters overridden by command-line arguments.")
        except Exception as e:
            logging.error(f"Error parsing command-line arguments: {e}")
            sys.exit(1)
    else:
        #logging.error(f"Error parsing command-line arguments: {e}")
        print("Add -h for help")
        sys.exit(1)


    # --- Initial State Setup ---
    if not os.path.isdir(LOG_DIR_TO_WATCH):
        logging.error(f"Log directory not found or is not a directory: {LOG_DIR_TO_WATCH}")
        sys.exit(1)

    logging.info(f"Initializing file positions in: {LOG_DIR_TO_WATCH}")
    for filename in LOG_FILE_CONFIG.keys():
        filepath = os.path.join(LOG_DIR_TO_WATCH, filename)
        if os.path.isfile(filepath):
            try:
                # Start tracking from the current end of the file
                file_positions[filepath] = os.path.getsize(filepath)
                logging.info(f" Initialized '{filename}' at position {file_positions[filepath]}.")
            except OSError as e:
                logging.error(f" Error accessing file {filepath}: {e}. Skipping.")
        else:
             logging.info(f" Log file '{filename}' not found initially. Will watch for creation.")


    # --- Setup Watchdog Observer ---
    event_handler = LogFileHandler(file_positions)
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR_TO_WATCH, recursive=False) # Non-recursive for flat dir

    logging.info(f"Starting log file monitor for directory: {LOG_DIR_TO_WATCH}")
    observer.start()
    logging.info("Monitor started. Press Ctrl+C to stop.")

    try:
        while True:
            # The main loop now just keeps the script alive and periodically checks
            # for inserting remaining rows based on the timeout.
            # watchdog runs in a separate thread.
            time.sleep(BATCH_TIMEOUT / 2) # Sleep briefly, check batches slightly more often than timeout
            check_and_insert_batches(force_insert=False)

    except KeyboardInterrupt:
        logging.info("Shutdown signal received.")
        logging.info("Attempting to insert any remaining pending rows...")
        check_and_insert_batches(force_insert=True) # Force insert remaining rows
    except Exception as e:
         logging.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
    finally:
        logging.info("Stopping file monitor...")
        observer.stop()
        observer.join()
        logging.info("Monitor stopped.")
