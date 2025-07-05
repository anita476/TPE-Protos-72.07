#include "../include/logger.h"

LOG_LEVEL current_level = DEBUG;
bool disabled = false;

void setLogLevel(LOG_LEVEL newLevel) {
	if (newLevel >= DEBUG && newLevel <= FATAL)
		current_level = newLevel;
}
void disableLogging() {
	disabled = true;
}

char *levelDescription(LOG_LEVEL level) {
	static char *description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
	if (level < DEBUG || level > FATAL)
		return "";
	return description[level];
}
