let editor = document.querySelector("#editor");

if (editor != null) {
    ace.edit(editor, {
        theme: "ace/theme/dracula", // "ace/theme/chrome"
        mode: "ace/mode/c_cpp",
        fontSize: "14pt"
    });
}

const switchButton = document.querySelector("#themeButton");
switchButton.addEventListener("click", () => {
    if (editor != null) {
        let theme = !editor.classList.contains("dark") ? "ace/theme/chrome" : "ace/theme/dracula";
        editor.classList.toggle("dark");
        editor.env.editor.setTheme(theme);
    }
    document.querySelector("body").classList.toggle("dark");
});
