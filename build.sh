#!/bin/bash
set -e

# Default max concurrency (0 means no limit)
MAX_CONCURRENCY=0

# Parse options
usage() {
  echo "Usage: $0 [-j max_concurrency] [app]"
  exit 1
}

while getopts "j:" opt; do
  case $opt in
    j)
      MAX_CONCURRENCY="$OPTARG"
      # Ensure it's a non-negative integer
      if ! [[ "$MAX_CONCURRENCY" =~ ^[0-9]+$ ]]; then
        echo "Error: Maximum concurrency must be a non-negative integer."
        exit 1
      fi
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

# Allow an optional app filter after the options.
if [ "$#" -gt 1 ]; then
  usage
fi

APP_FILTER=""
if [ "$#" -eq 1 ]; then
  APP_FILTER="$1"
fi

# Create output and logs directories
mkdir -p build
mkdir -p build/logs

# Arrays to keep track of background jobs
declare -a pids
declare -a app_names
declare -a log_files

# Function to build a single app.
build_app() {
  local app="$1"
  local logfile="$2"

  {
    echo "=========================================="
    echo "Processing application: $app"
    echo "=========================================="

    pushd "$app" > /dev/null

    # Skip if no .go files exist.
    if ! ls *.go 1> /dev/null 2>&1; then
      echo "No .go files found in $app, skipping."
      popd > /dev/null
      exit 0
    fi

    # Initialize go.mod if needed.
    if [ ! -f "go.mod" ]; then
      echo "go.mod not found in $app. Initializing module..."
      go mod init "$app"
    fi

    echo "Running go mod tidy for $app..."
    go mod tidy

    # Build for multiple platforms.
    echo "Building Linux (amd64) for $app..."
    env GOOS=linux GOARCH=amd64 go build -o ../build/${app}-linux-amd64 .

    echo "Building macOS (amd64) for $app..."
    env GOOS=darwin GOARCH=amd64 go build -o ../build/${app}-darwin-amd64 .

    echo "Building Windows (amd64) for $app..."
    env GOOS=windows GOARCH=amd64 go build -o ../build/${app}-windows-amd64.exe .

    echo "Building Raspberry Pi 32-bit (linux/arm) for $app..."
    env GOOS=linux GOARCH=arm go build -o ../build/${app}-linux-arm .

    echo "Building Raspberry Pi 64-bit (linux/arm64) for $app..."
    env GOOS=linux GOARCH=arm64 go build -o ../build/${app}-linux-arm64 .

    popd > /dev/null
  } &> "$logfile"
}

found=0

# Iterate over each subdirectory (excluding "build") and start a background build job.
for d in */ ; do
  APP_NAME="${d%/}"
  
  # Skip the build directory
  if [ "$APP_NAME" == "build" ]; then
    continue
  fi
  
  # If an app filter is specified, skip directories that don't match.
  if [ -n "$APP_FILTER" ] && [ "$APP_NAME" != "$APP_FILTER" ]; then
    continue
  fi

  found=1
  log_file="build/logs/${APP_NAME}.log"
  echo "Starting build for application: $APP_NAME (log: $log_file)"
  
  # Start the build in the background.
  build_app "$APP_NAME" "$log_file" &
  pid=$!
  pids+=("$pid")
  app_names+=("$APP_NAME")
  log_files+=("$log_file")

  # If a max concurrency limit is set, wait until the number of running jobs drops below it.
  if [ "$MAX_CONCURRENCY" -gt 0 ]; then
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_CONCURRENCY" ]; do
      sleep 0.1
    done
  fi

  # If an app filter was provided, build only that one.
  if [ -n "$APP_FILTER" ]; then
    break
  fi
done

# If an app filter was specified and no matching directory was found, exit with an error.
if [ -n "$APP_FILTER" ] && [ "$found" -eq 0 ]; then
  echo "Error: No directory matching '$APP_FILTER' found."
  exit 1
fi

# Wait for all background jobs to finish.
exit_status=0
for i in "${!pids[@]}"; do
  if ! wait "${pids[$i]}"; then
    echo "Build failed for ${app_names[$i]}. Check its log file: ${log_files[$i]}"
    exit_status=1
  fi
done

# After all builds complete, print each app's output.
for i in "${!app_names[@]}"; do
  echo ""
  echo "=========================================="
  echo "Output for ${app_names[$i]}:"
  echo "=========================================="
  cat "${log_files[$i]}"
done

exit $exit_status

