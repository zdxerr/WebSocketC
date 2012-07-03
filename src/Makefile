
SOURCES = sha1.c base64.c list.c server.c
HEADERS = sha1.h base64.h list.h server.h
OBJECTS = $(SOURCES:.c=.obj)
TARGET  = server.lib

# file system commands
RM = del /F /Q
CP = xcopy
MV = move

CFLAGS  = /nologo /MTd
LFLAGS  = /nologo /out:$(TARGET)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	lib $(LFLAGS) $(OBJECTS)

*.obj: $(HEADERS)

clean:
	$(RM) *.obj
	$(RM) *.lib
