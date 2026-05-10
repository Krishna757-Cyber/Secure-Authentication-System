# ──────────────────────────────────────────────────────────
#  Makefile – Secure Authentication System
#  Usage:
#    make            → build authen (Linux/macOS)
#    make windows    → build authen.exe (MinGW on Windows)
#    make clean      → remove compiled output
# ──────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11
SRCS    = main.c functions.c
HEADERS = functions.h
TARGET  = authen

# Default: Linux / macOS
all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)
	@echo "[+] Build successful: ./$(TARGET)"

# Windows (MinGW)
windows:
	$(CC) $(CFLAGS) -o authen.exe $(SRCS)
	@echo "[+] Build successful: authen.exe"

# Clean up
clean:
	rm -f $(TARGET) authen.exe credentials.dat security.log
	@echo "[+] Clean complete."

.PHONY: all windows clean
