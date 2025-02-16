#!/bin/bash
set -e

# Create output directory
mkdir -p build

# Iterate over each subdirectory, excluding the build directory
for d in */ ; do
  # Remove the trailing slash
  APP_NAME="${d%/}"
  
  # Skip the build directory
  if [ "$APP_NAME" == "build" ]; then
    continue
  fi

  echo "=========================================="
  echo "Processing application: $APP_NAME"
  echo "=========================================="
  
  # Change to the application directory
  pushd "$APP_NAME" > /dev/null
  
  # Check if there is at least one .go file in the directory
  if ! ls *.go 1> /dev/null 2>&1; then
    echo "No .go files found in $APP_NAME, skipping."
    popd > /dev/null
    continue
  fi

  # If go.mod does not exist, initialize it with module name equal to APP_NAME
  if [ ! -f "go.mod" ]; then
    echo "go.mod not found in $APP_NAME. Initializing module..."
    go mod init "$APP_NAME"
  fi
  
  # Tidy up the module dependencies
  echo "Running go mod tidy for $APP_NAME..."
  go mod tidy
  
  # Build for multiple platforms
  echo "Building Linux (amd64) for $APP_NAME..."
  env GOOS=linux GOARCH=amd64 go build -o ../build/${APP_NAME}-linux-amd64 .

  echo "Building macOS (amd64) for $APP_NAME..."
  env GOOS=darwin GOARCH=amd64 go build -o ../build/${APP_NAME}-darwin-amd64 .

  echo "Building Windows (amd64) for $APP_NAME..."
  env GOOS=windows GOARCH=amd64 go build -o ../build/${APP_NAME}-windows-amd64.exe .

  echo "Building Raspberry Pi 32-bit (linux/arm) for $APP_NAME..."
  env GOOS=linux GOARCH=arm go build -o ../build/${APP_NAME}-linux-arm .

  echo "Building Raspberry Pi 64-bit (linux/arm64) for $APP_NAME..."
  env GOOS=linux GOARCH=arm64 go build -o ../build/${APP_NAME}-linux-arm64 .
  
  # Return to the root directory
  popd > /dev/null
done

