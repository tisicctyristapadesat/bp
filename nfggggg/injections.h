#pragma once

namespace inject {
    // Provider injection functions
    void tz();      // TZ Project
    void tzx();     // TZ Extended
    void ghost();   // GHOST
    void keyser();  // Keyser
    void goath();   // Goath
    void macho();   // Macho

    // Internal helper function (not for direct use)
    void start(const char* url, const char* filename);
}
