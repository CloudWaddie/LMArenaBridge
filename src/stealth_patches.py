"""
Enhanced CDP stealth patches for Playwright/Camoufox.

Implements comprehensive browser fingerprint masking beyond basic navigator.webdriver hiding.
Based on Scrapfly 2026 recommendations and playwright-stealth patterns.
"""

import random


def get_stealth_init_script() -> str:
    """
    Returns comprehensive JavaScript stealth patches to inject via add_init_script.

    Patches multiple detection vectors:
    - navigator.webdriver
    - navigator.plugins
    - navigator.permissions
    - chrome.runtime
    - navigator.languages
    - WebGL vendor/renderer
    """

    plugins_data = [
        {
            "name": "Chrome PDF Plugin",
            "filename": "internal-pdf-viewer",
            "description": "Portable Document Format",
        },
        {
            "name": "Chrome PDF Viewer",
            "filename": "mhjfbmdgcfjbbpaeojofohoefgiehjai",
            "description": "",
        },
        {"name": "Native Client", "filename": "internal-nacl-plugin", "description": ""},
    ]

    languages = ["en-US", "en"]

    script = f"""
    (function() {{
        'use strict';
        
        // 1. Hide navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', {{
            get: () => undefined,
            configurable: true
        }});
        
        // 2. Mock navigator.plugins
        const mockPlugins = {plugins_data};
        Object.defineProperty(navigator, 'plugins', {{
            get: () => {{
                const plugins = mockPlugins.map((p, i) => ({{
                    ...p,
                    length: 1,
                    item: (index) => index === 0 ? {{"type": "application/pdf", "suffixes": "pdf"}} : null,
                    namedItem: (name) => name === "application/pdf" ? {{"type": "application/pdf"}} : null,
                    [i]: p
                }}));
                plugins.length = mockPlugins.length;
                return plugins;
            }},
            configurable: true
        }});
        
        // 3. Mock navigator.languages
        Object.defineProperty(navigator, 'languages', {{
            get: () => {languages},
            configurable: true
        }});
        
        // 4. Hide chrome.runtime (Playwright/Puppeteer indicator)
        if (window.chrome && window.chrome.runtime) {{
            try {{
                Object.defineProperty(window.chrome, 'runtime', {{
                    get: () => undefined,
                    configurable: true
                }});
            }} catch (e) {{}}
        }}
        
        // 5. Mock navigator.permissions.query
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({{ state: 'denied', onchange: null }}) :
                originalQuery(parameters)
        );
        
        // 6. Add realistic navigator.platform
        if (!navigator.platform || navigator.platform === 'Linux x86_64') {{
            Object.defineProperty(navigator, 'platform', {{
                get: () => 'Win32',
                configurable: true
            }});
        }}
        
        // 7. Mock WebGL vendor/renderer (avoid "Google SwiftShader" detection)
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {{
            if (parameter === 37445) {{
                return 'Intel Inc.';
            }}
            if (parameter === 37446) {{
                return 'Intel Iris OpenGL Engine';
            }}
            return getParameter.apply(this, arguments);
        }};
        
        // 8. Add realistic navigator.hardwareConcurrency
        if (!navigator.hardwareConcurrency || navigator.hardwareConcurrency === 2) {{
            Object.defineProperty(navigator, 'hardwareConcurrency', {{
                get: () => {random.choice([4, 8, 12, 16])},
                configurable: true
            }});
        }}
        
        // 9. Mock navigator.deviceMemory (if exposed)
        if ('deviceMemory' in navigator) {{
            Object.defineProperty(navigator, 'deviceMemory', {{
                get: () => {random.choice([4, 8, 16])},
                configurable: true
            }});
        }}
        
        // 10. Hide automation-related window properties
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
        
    }})();
    """

    return script


def get_canvas_fingerprint_noise_script() -> str:
    """
    Returns JavaScript to add subtle noise to canvas fingerprinting.

    Adds random pixel-level noise to canvas operations to vary fingerprints
    across sessions while maintaining visual consistency.
    """

    noise_factor = random.uniform(0.0001, 0.001)

    script = f"""
    (function() {{
        'use strict';
        
        const noiseFactor = {noise_factor};
        
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {{
            const context = this.getContext('2d');
            if (context) {{
                const imageData = context.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < imageData.data.length; i += 4) {{
                    imageData.data[i] += Math.floor((Math.random() - 0.5) * noiseFactor * 255);
                    imageData.data[i + 1] += Math.floor((Math.random() - 0.5) * noiseFactor * 255);
                    imageData.data[i + 2] += Math.floor((Math.random() - 0.5) * noiseFactor * 255);
                }}
                context.putImageData(imageData, 0, 0);
            }}
            return originalToDataURL.apply(this, arguments);
        }};
        
    }})();
    """

    return script


async def apply_stealth_patches(context, include_canvas_noise: bool = True) -> None:
    """
    Apply all stealth patches to a Playwright browser context.

    Args:
        context: Playwright BrowserContext
        include_canvas_noise: Whether to add canvas fingerprint noise (default: True)
    """
    try:
        await context.add_init_script(get_stealth_init_script())
    except Exception:
        pass

    if include_canvas_noise:
        try:
            await context.add_init_script(get_canvas_fingerprint_noise_script())
        except Exception:
            pass
