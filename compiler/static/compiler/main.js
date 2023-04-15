let editor = document.querySelector("#editor");

ace.edit(editor, {
    theme: "ace/theme/dracula", // "ace/theme/chrome"
    mode: "ace/mode/c_cpp",
    fontSize: "14pt",
    value: '#include <stdio.h>\n\nint main() {\n\tprintf("Hello, World!");\n\treturn 0;\n}\n'
});

const swtichButton = document.querySelector("#themeButton");
swtichButton.addEventListener("click", () => {
    let theme = !editor.classList.contains("dark") ? "ace/theme/chrome" : "ace/theme/dracula";
    editor.classList.toggle("dark");
    editor.env.editor.setTheme(theme);
    document.querySelector("body").classList.toggle("dark");
});
