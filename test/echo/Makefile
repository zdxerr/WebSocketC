
SOURCES = echo_server.c
HEADERS =
OBJECTS = $(SOURCES:.c=.obj)
TARGET  = echo.exe

# file system commands
RM = del /F /Q
CP = xcopy
MV = move

CFLAGS = /nologo /MTd /I"..\..\src"
LFLAGS = /nologo /out:$(TARGET) /LIBPATH:"..\..\src"

all: $(TARGET)

$(TARGET): $(OBJECTS)
	link $(LFLAGS) $(OBJECTS)

*.obj: $(HEADERS)

clean:
	$(RM) *.obj
	$(RM) *.exe

