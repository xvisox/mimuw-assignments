// Load previously chosen file
let id = localStorage.getItem('file_id');
if (id !== null) chooseFile(id);

function chooseFile(id) {
    localStorage.setItem('file_id', id);
    $.ajax({
        url: 'files/' + id + '/show',
        type: 'GET',
        success: function (data) {
            $('#editor').text(data['code']);
        },
        error: function (data) {
            console.log(data);
        }
    });
}

function dropFile() {
    localStorage.removeItem('file_id');
}

function compileFile() {
    let id = localStorage.getItem('file_id');
    if (id === null) return; // No file chosen

    let form = $('#compile-form').attr('action', 'files/' + id + '/compile');
    $.ajax({
        type: form.attr('method'),
        url: form.attr('action'),
        data: form.serialize(),
        success: function (data) {
            // Display output
            let cmd = "<p>" + data['cmd'] + "</p>";
            let lines = data['output'];
            for (let i = 0; i < lines.length; i++) {
                lines[i] = "<pre class=\"line\">" + lines[i] + "</pre>";
            }
            $('#output').html(cmd + lines.join(''));
        },
        error: function (data) {
            console.log('An error occurred.');
            console.log(data);
        },
    });
}

function changeSections() {
    let id = localStorage.getItem('file_id');
    if (id === null) return; // No file chosen

    let textarea = document.querySelector("textarea")
    let start = textarea.selectionStart;
    let end = textarea.selectionEnd;
    // Calculate row numbers
    let rowStart = textarea.value.substr(0, start).split("\n").length - 1;
    let rowEnd = textarea.value.substr(0, end).split("\n").length - 1;

    // Fill form and send request
    let form = $('#sections-form').attr('action', 'files/' + id + '/sections');
    form.find('input[name="start"]').val(rowStart);
    form.find('input[name="end"]').val(rowEnd);
    $.ajax({
        type: form.attr('method'),
        url: form.attr('action'),
        data: form.serialize(),
        success: function () {
            chooseFile(id);
        }
    });
}
