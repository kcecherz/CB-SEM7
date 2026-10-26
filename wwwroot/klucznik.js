window.klucznik = window.klucznik || {};

window.klucznik.toggleSecret = (id, button) => {
    const input = document.getElementById(id);
    if (!input) return;
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    if (button) button.textContent = reveal ? "Ukryj" : "Pokaż";
};

window.klucznik.watchActivity = (dotNet) => {
    window.klucznik._dotNet = dotNet;
    if (window.klucznik._watching) return;
    window.klucznik._watching = true;

    let last = 0;
    const bump = () => {
        const now = Date.now();
        if (now - last < 15000) return;
        last = now;
        const target = window.klucznik._dotNet;
        if (target) target.invokeMethodAsync("Touch");
    };

    ["pointerdown", "keydown", "scroll"].forEach((name) => {
        document.addEventListener(name, bump, { passive: true });
    });
    bump();
};
