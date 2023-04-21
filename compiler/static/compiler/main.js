let editor = document.querySelector("#editor");
const switchButton = document.querySelector("#themeButton");
let theme = localStorage.getItem("theme") || "dark";
switchButton.addEventListener("click", () => {
    if (theme === "dark") {
        document.querySelector("body").classList.add("light");
        ace.edit(editor).setTheme("ace/theme/chrome");
        theme = "light";
    } else {
        document.querySelector("body").classList.remove("light");
        ace.edit(editor).setTheme("ace/theme/dracula");
        theme = "dark";
    }
    localStorage.setItem("theme", theme);
});

if (theme === "light") {
    document.querySelector("body").classList.add("light");
}
