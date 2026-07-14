# Firewall Build System
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS  := -L./vendor/lib -lnetfilter_queue -lmnl -lpthread -Wl,-rpath,'$$ORIGIN/vendor/lib'

INCLUDES := -I./src -I./vendor/include

SRC_DIR  := src
BUILD_DIR := build
TARGET   := firewall

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))

.PHONY: all clean install deps check debug

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS) vendor/lib/libnetfilter_queue.so
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[*] Built: $(TARGET)"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "[*] Installed to /usr/local/bin/$(TARGET)"

deps:
	@echo "[*] Checking dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		if ! dpkg -s libnetfilter-queue-dev >/dev/null 2>&1; then \
			echo "[*] Installing libnetfilter-queue-dev (Debian/Ubuntu)..."; \
			sudo apt-get update && sudo apt-get install -y libnetfilter-queue-dev; \
		fi; \
	elif command -v pacman >/dev/null 2>&1; then \
		if ! pacman -Qi libnetfilter_queue >/dev/null 2>&1; then \
			echo "[*] Installing libnetfilter_queue (Arch)..."; \
			sudo pacman -S --needed --noconfirm libnetfilter_queue; \
		fi; \
	elif command -v dnf >/dev/null 2>&1; then \
		if ! rpm -q libnetfilter_queue-devel >/dev/null 2>&1; then \
			echo "[*] Installing libnetfilter_queue-devel (Fedora/RHEL)..."; \
			sudo dnf install -y libnetfilter_queue-devel; \
		fi; \
	elif command -v zypper >/dev/null 2>&1; then \
		if ! rpm -q libnetfilter_queue-devel >/dev/null 2>&1; then \
			echo "[*] Installing libnetfilter_queue-devel (openSUSE)..."; \
			sudo zypper install -y libnetfilter_queue-devel; \
		fi; \
	fi
	@echo "[*] Dependencies OK"

check:
	@echo "=== Firewall Build Check ==="
	@echo "CXX:      $(CXX)"
	@echo "CXXFLAGS: $(CXXFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"
	@echo "Sources:  $(SRCS)"
	@echo "Objects:  $(OBJS)"
	@echo "Target:   $(TARGET)"
	@test -f vendor/include/libnetfilter_queue/libnetfilter_queue.h && \
		echo "NFQueue headers: FOUND" || echo "NFQueue headers: MISSING"
	@test -f vendor/lib/libnetfilter_queue.so && \
		echo "NFQueue library: FOUND" || echo "NFQueue library: MISSING"

debug: CXXFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS  += -fsanitize=address
debug: clean all
	@echo "[*] Debug build complete"
