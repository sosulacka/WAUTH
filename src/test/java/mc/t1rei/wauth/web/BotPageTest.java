package mc.t1rei.wauth.web;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class BotPageTest {
    private String page(String username) {
        var response = new Router(null, username).route("GET", "/setup", null, null, null);
        assertEquals(200, response.status());
        return new String(response.body(), StandardCharsets.UTF_8);
    }

    @Test void usesConfiguredBot() {
        String html = page("@example_bot");
        assertTrue(html.contains("href=\"https://t.me/example_bot\""));
        assertTrue(html.contains("<strong>@example_bot</strong>"));
    }

    @Test void missingOrInvalidBotDisablesLink() {
        for (String username : new String[]{"", " ", "\"><script>alert(1)</script>"}) {
            String html = page(username);
            assertTrue(html.contains("id=\"open-bot\" aria-disabled=\"true\""));
            assertFalse(html.contains("https://t.me/"));
        }
    }

    @Test void selectsPlatformAndRejectsUnsupportedSystems() {
        assertEquals("bin/cloudflared-windows-amd64.exe", TunnelService.binaryResource("Windows 11", "amd64"));
        assertEquals("bin/cloudflared-linux-amd64", TunnelService.binaryResource("Linux", "x86_64"));
        assertThrows(IllegalArgumentException.class, () -> TunnelService.binaryResource("Darwin", "amd64"));
        assertThrows(IllegalArgumentException.class, () -> TunnelService.binaryResource("Linux", "aarch64"));
    }
}
