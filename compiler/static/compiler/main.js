// Load previously chosen file
let id = localStorage.getItem('file_id');
if (id !== null) displayFileAndSaveId(id);

function displayFileAndSaveId(id) {
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

function saveFileIdToForm(id, name) {
    localStorage.setItem('form_id', id);
    $('#exampleModalLabel').text('Chosen directory: ' + name);
}

function dropLocalStorage() {
    localStorage.removeItem('file_id');
    localStorage.removeItem('form_id');
}

function compileFile() {
    let id = localStorage.getItem('file_id');
    if (id === null) return; // No file chosen

    let form = $('#compile-form').attr('action', 'files/' + id + '/compile');
    $.ajax({
        url: form.attr('action'),
        type: form.attr('method'),
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

    // Get selected text
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
        url: form.attr('action'),
        type: form.attr('method'),
        data: form.serialize(),
        success: function () {
            displayFileAndSaveId(id);
        }
    });
}

function refreshTree() {
    let tree = $('#tree');
    $.ajax({
        url: 'files/tree',
        type: 'GET',
        success: function (data) {
            console.log('Refreshing tree.');
            tree.html(data);
        }
    })
}

function uploadFile() {
    let id = localStorage.getItem('form_id');
    let form = $('#upload-form').attr('action', 'files/upload');
    // Set parent id in the form
    form.find('input[name="parent"]').val(id);

    $.ajax({
        url: form.attr('action'),
        type: form.attr('method'),
        data: new FormData(form[0]),
        processData: false,
        contentType: false,
        success: function () {
            console.log('File uploaded.');
        }, error: function (data) {
            console.log(data);
        },
        async: false
    })
    refreshTree();
}

function deleteFile() {
    let id = localStorage.getItem('form_id');
    if (id === null) return; // No file chosen

    $.ajax({
        url: 'files/' + id + '/delete',
        type: 'DELETE',
        async: false
    })
    refreshTree();
}

function createDirectory() {
    let id = localStorage.getItem('form_id');
    if (id === null) return; // No file chosen

    let form = $('#create-directory-form').attr('action', 'files/directory/create');
    // Set parent id in the form
    form.find('input[name="parent"]').val(id);

    $.ajax({
        url: form.attr('action'),
        type: form.attr('method'),
        data: form.serialize(),
        success: function () {
            console.log('Directory created.');
        }, error: function (data) {
            console.log(data);
        },
        async: false
    })
    refreshTree();
}