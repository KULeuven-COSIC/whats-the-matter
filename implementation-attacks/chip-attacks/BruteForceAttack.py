import subprocess
import time
import os
import signal
import re
import sys
import threading # for device logging
import numpy as np


# --- Configuration ---
CHIP_TOOL_BUILD_DIR = "" # Add here the directory of chip-tool
CHIP_TOOL_EXEC = os.path.join(CHIP_TOOL_BUILD_DIR, "chip-tool")

LIGHTING_APP_BUILD_DIR = "" # Add here the directory of lighting-app (lighting-app/linux/out/debug)
LIGHTING_APP_EXEC = os.path.join(LIGHTING_APP_BUILD_DIR, "chip-lighting-app")
LIGHTING_APP_KVS = "/tmp/chip_kvs" # default KVS path for linux example

TARGET_DISCRIMINATOR = 3840
CORRECT_PASSCODE = 20191960 # to avoid accidentally hitting this
NODE_ID_TO_ASSIGN = 5      # temporary Node ID for commissioning attempts

ATTEMPTS_PER_CYCLE = 20
MAX_CYCLES = 10 # #cycles (20 attempts each) to run
CHIP_TOOL_TIMEOUT_S = 7 # timeout for each chip-tool command (seconds)

# --- Globals ---
device_process = None
current_passcode = 20202020 # starting incorrect passcode
total_attempts_overall = 0
device_log_thread = None # added for logging thread
stop_logging_event = threading.Event() # added for signaling thread stop

# --- Functions ---

def log_device_output(process_stdout):
    """Reads and prints lines from the device process stdout."""
    try:
        # reads line by line until the event is set or the stream closes
        for line in iter(process_stdout.readline, ''):
            if stop_logging_event.is_set():
                break
            print(f"[DEVICE] {line.strip()}")
        process_stdout.close() # Ensure the pipe is closed
        print("[INFO] Device logging thread finished.")
    except Exception as e:
        # handles potential exceptions during reading, e.g., if process dies unexpectedly
        if not stop_logging_event.is_set():
             print(f"[ERROR] Exception in device logging thread: {e}", file=sys.stderr)

def start_device():
    """Stops previous device, clears KVS, starts new device process and logging thread."""
    global device_process, device_log_thread, stop_logging_event
    stop_device() # ensuring any previous instance is stopped

    # clearing KVS
    if os.path.exists(LIGHTING_APP_KVS):
        print(f"INFO: Removing KVS file: {LIGHTING_APP_KVS}")
        try:
            os.remove(LIGHTING_APP_KVS)
        except OSError as e:
            print(f"ERROR: Failed to remove KVS file: {e}", file=sys.stderr)

    print("INFO: Starting lighting-app...")
    try:
        # resetting the stop event for the new process
        stop_logging_event.clear()

        # starting the device process
        device_process = subprocess.Popen(
            [LIGHTING_APP_EXEC],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid
        )

        # starting the logging thread
        device_log_thread = threading.Thread(
            target=log_device_output,
            args=(device_process.stdout,),
            daemon=True # set as daemon so it doesn't block script exit if main thread dies
        )
        device_log_thread.start()

        # waiting for the device to be ready (checking readiness via logs printed by the thread)
        print("INFO: Waiting a few seconds for device to initialize...")
        time.sleep(5) 

        # basic check if process started okay
        if device_process.poll() is not None:
             print("ERROR: lighting-app exited immediately after starting.", file=sys.stderr)
             stop_device()
             return False

        print("INFO: Assuming lighting-app is ready.")
        return True

    except FileNotFoundError:
        print(f"ERROR: lighting-app executable not found at {LIGHTING_APP_EXEC}", file=sys.stderr)
        device_process = None
        return False
    except Exception as e:
        print(f"ERROR: Failed to start lighting-app: {e}", file=sys.stderr)
        device_process = None
        return False

def stop_device():
    """Stops the logging thread and the lighting-app process."""
    global device_process, device_log_thread, stop_logging_event

    # signals and waits for the logging thread to finish
    if device_log_thread and device_log_thread.is_alive():
        print("INFO: Signaling logging thread to stop...")
        stop_logging_event.set()
        device_log_thread.join(timeout=2) # waiting briefly for thread to exit
        if device_log_thread.is_alive():
            print("WARNING: Logging thread did not stop gracefully.")
        device_log_thread = None

    # stopping the device process
    if device_process and device_process.poll() is None:
        print("INFO: Stopping lighting-app process...")
        try:
            os.killpg(os.getpgid(device_process.pid), signal.SIGTERM)
            device_process.wait(timeout=5)
            print("INFO: lighting-app process stopped.")
        except ProcessLookupError:
             print("INFO: lighting-app process already gone.")
        except subprocess.TimeoutExpired:
            print("WARNING: lighting-app did not terminate gracefully, sending SIGKILL.")
            try:
                os.killpg(os.getpgid(device_process.pid), signal.SIGKILL)
                device_process.wait(timeout=2)
            except Exception as e:
                print(f"ERROR: Failed to kill lighting-app: {e}", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: Error stopping lighting-app process: {e}", file=sys.stderr)
        finally:
            if device_process.stdout:
                device_process.stdout.close()
            device_process = None

def run_chip_tool_attempt(passcode):
    """Runs a single chip-tool pairing attempt."""
    cmd = [
        CHIP_TOOL_EXEC,
        "pairing",
        "onnetwork-long",
        str(NODE_ID_TO_ASSIGN),
        str(passcode),
        str(TARGET_DISCRIMINATOR),
        "--timeout",
        str(CHIP_TOOL_TIMEOUT_S)
    ]
    print(f"  Attempting passcode: {passcode} ... ", end="")
    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=CHIP_TOOL_TIMEOUT_S + 5
        )
        duration = time.time() - start_time

        if result.returncode == 0:
            print(f"SUCCESS (Unexpected!) - Duration: {duration:.2f}s")
            return "success"
        elif "CHIP Error 0x000000AC" in result.stderr or "CHIP Error 0x000000AC" in result.stdout:
            print(f"FAIL (Wrong Passcode Error 0xAC) - Duration: {duration:.2f}s")
            return "wrong_passcode"
        elif "CHIP Error 0x00000032" in result.stderr or "CHIP Error 0x00000032" in result.stdout:
            # printing chip-tool output only on timeout to see discovery details
            print("\n----- chip-tool stdout (Timeout) -----")
            print(result.stdout.strip())
            print("----- chip-tool stderr (Timeout) -----")
            print(result.stderr.strip())
            print("--------------------------------------")
            print(f"FAIL (Timeout Error 0x32) - Duration: {duration:.2f}s")
            return "timeout"
        else:
            print(f"FAIL (Unknown Error, Code: {result.returncode}) - Duration: {duration:.2f}s")
            print(f"----- chip-tool stdout -----\n{result.stdout}\n--------------------------")
            print(f"----- chip-tool stderr -----\n{result.stderr}\n--------------------------")
            return "other_error"

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        print(f"FAIL (Command Timeout) - Duration: {duration:.2f}s")
        return "timeout"
    except FileNotFoundError:
        print(f"ERROR: chip-tool executable not found at {CHIP_TOOL_EXEC}", file=sys.stderr)
        return "fatal"
    except Exception as e:
        print(f"FAIL (Script Exception: {e})")
        return "fatal"

# --- Main Execution ---

print("Starting Commissioning Brute-Force Test...")
print(f"Device: {LIGHTING_APP_EXEC}")
print(f"Controller: {CHIP_TOOL_EXEC}")
print(f"Attempts per cycle: {ATTEMPTS_PER_CYCLE}")
print("-" * 30)

cycle_num = 0
overall_start_time = time.time()

# lists to store timing data for statistical analysis

try: # try block for nice cleanup on Ctrl+C
    while MAX_CYCLES is None or cycle_num < MAX_CYCLES:
        cycle_num += 1
        print(f"\n--- Cycle {cycle_num} ---")
        cycle_start_time = time.time()

        # measuring time to restart the commissioning session
        restart_start_time = time.time()
        if not start_device():
            print("ERROR: Failed to start device. Aborting.", file=sys.stderr)
            break
        restart_duration = time.time() - restart_start_time
        print(f"INFO: Time to restart commissioning session: {restart_duration:.2f} seconds")

        print(f"INFO: Device started. Beginning {ATTEMPTS_PER_CYCLE} commissioning attempts...")
        attempts_this_cycle = 0
        lockout_suspected = False

        # measuring time for 20 attempts
        attempts_start_time = time.time()       
        for i in range(ATTEMPTS_PER_CYCLE):
            attempts_this_cycle += 1
            total_attempts_overall += 1

            if current_passcode == CORRECT_PASSCODE:
                current_passcode += 1

            result = run_chip_tool_attempt(current_passcode)

            if result == "success":
                print("ERROR: Commissioning succeeded with wrong passcode! Check device/tool.", file=sys.stderr)
                break
            elif result == "wrong_passcode":
                pass
            elif result == "timeout":
                if i > 3:
                     print("INFO: Timeout occurred, potentially due to device lockout.")
                     lockout_suspected = True
                else:
                     print("INFO: Timeout occurred early in cycle.")
            elif result == "fatal" or result == "other_error":
                print("ERROR: Unrecoverable error during chip-tool execution. Aborting.", file=sys.stderr)
                sys.exit(1)

            current_passcode += 1

        attempts_duration = time.time() - attempts_start_time
        print(f"INFO: Time for {ATTEMPTS_PER_CYCLE} attempts: {attempts_duration:.2f} seconds")    

        cycle_duration = time.time() - cycle_start_time
        print(f"--- Cycle {cycle_num} Finished ---")
        print(f"Attempts in this cycle: {attempts_this_cycle}")
        print(f"Passcodes tried: {current_passcode - attempts_this_cycle} to {current_passcode - 1}")
        print(f"Cycle duration: {cycle_duration:.2f} seconds")
        if lockout_suspected:
            print("INFO: Lockout was suspected during this cycle (based on timeouts).")

        stop_device()

except KeyboardInterrupt: # handler for Ctrl+C
    print("\nINFO: KeyboardInterrupt received. Cleaning up...")

finally: # ensuring device is stopped on exit or error
    print("INFO: Performing final cleanup...")
    stop_device()

    overall_duration = time.time() - overall_start_time
    print("\n--- Test Finished ---")
    print(f"Total cycles completed: {cycle_num}")
    print(f"Total attempts overall: {total_attempts_overall}")
    print(f"Last passcode tried: {current_passcode - 1}")
    print(f"Total duration: {overall_duration:.2f} seconds")
    if total_attempts_overall > 0:
        print(f"Average time per attempt: {overall_duration / total_attempts_overall:.2f} seconds")   