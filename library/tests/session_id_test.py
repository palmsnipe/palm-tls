#!/usr/bin/env python3
"""Exercise the actual resident ID allocator across wrap with retained profiles."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
source=(root/'src/palm_library.c').read_text()
function=source[source.index('static UInt32 NextSessionId('):source.index('static Boolean EngineResourcesPresent(')]
with tempfile.TemporaryDirectory() as directory:
    path=Path(directory)
    unit=path/'test.c'
    unit.write_text('''
#include <stdint.h>
#include <assert.h>
#include <string.h>
typedef uint16_t UInt16;
typedef uint32_t UInt32;
#define PALM_TLS_MAX_SESSIONS 2
typedef struct {
    UInt32 sessionId;
    struct { UInt16 enabled; struct { UInt32 sessionId; } result; } profiler;
} PalmTlsEngineControl;
typedef struct {
    UInt16 nextSessionId;
    struct { PalmTlsEngineControl controls[2]; } engine;
} PalmTlsLibraryState;
'''+function+'''
int main(void) {
    PalmTlsLibraryState state;
    int i;
    memset(&state,0,sizeof(state));
    assert(NextSessionId(&state)==1);
    state.nextSessionId=65534;
    state.engine.controls[0].sessionId=65535;
    state.engine.controls[1].profiler.enabled=1;
    state.engine.controls[1].profiler.result.sessionId=1;
    assert(NextSessionId(&state)==2);
    state.engine.controls[0].profiler.enabled=1;
    state.engine.controls[0].profiler.result.sessionId=3;
    assert(NextSessionId(&state)==4);
    for(i=0;i<70000;i++) {
        UInt32 id=NextSessionId(&state);
        assert(id && id!=65535 && id!=1 && id!=3);
    }
    return 0;
}
''')
    binary=path/'test'
    subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-std=c17','-Wall','-Wextra','-Werror',str(unit),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('Session ID wrap preserves active sessions and retained profiles')
