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
    if (id === '-1') {
        $('#upload-tab').addClass('disabled');
        $('#delete-btn').addClass('disabled');
        $('#upload-btn').addClass('disabled');
    } else {
        $('#upload-tab').removeClass('disabled');
        $('#delete-btn').removeClass('disabled');
        $('#upload-btn').removeClass('disabled');
    }
}

function dropLocalStorage() {
    localStorage.removeItem('file_id');
    localStorage.removeItem('form_id');
}

function highlightLine(line) {
    let editor = document.querySelector("textarea")
    let lines = editor.value.split('\n'); // split the text into an array of lines
    let start = 0;
    let end = 0;

    // find the starting and ending indices of the specified line
    for (let i = 0; i < lines.length; i++) {
        if (i < line - 1) {
            start += lines[i].length + 1; // add 1 to account for the newline character
        }
        if (i === line - 1) {
            end = start + lines[i].length; // end index is start index plus line length
            break;
        }
    }

    editor.scrollTop = editor.scrollHeight * (line - 1) / lines.length;
    // Scroll to the highlighted line
    editor.setSelectionRange(start, end);
    editor.scrollIntoView({behavior: 'smooth', block: 'center'});
    editor.focus();
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
            let headers = data['headers'];
            let bodies = data['bodies']
            for (let i = 0; i < bodies.length; i++) {
                headers[i] = '<pre class="section-header line">' + headers[i] + '</pre>';
                bodies[i] = '<pre class="section-body line">' + bodies[i] + '</pre>';
            }
            let result = []
            for (let i = 0; i < headers.length; i++) {
                result.push(headers[i] + bodies[i]);
            }
            let output = $('#output');
            output.html(cmd + result.join(''));

            // Add click event listener to each section-header
            $('.section-header').click(function () {
                // Toggle visibility of the section-body immediately following the clicked section-header
                $(this).next('.section-body').toggle();
            });

            // Create a new button element to show/hide all section bodies
            const toggleButton = $('<button>').text('Show/Hide All').addClass('btn btn-outline-light show-hide-btn')
            toggleButton.click(function () {
                $('.section-body').toggle();
            });

            // Add the toggle button to the output element
            output.prepend(toggleButton);
        },
        error: function (data) {
            data = data['responseJSON'];
            let cmd = "<p>" + data['cmd'] + "</p>";
            let errors = data['errors']
            let lines = []
            for (let i = 0; i < errors.length; i++) {
                let errorLineNumber = errors[i][1];
                if (errorLineNumber !== '-1') {
                    lines.push('<pre class="line" data-line="' + errorLineNumber + '">' + errors[i][0] + '</pre>');
                } else {
                    lines.push('<pre class="line">' + errors[i][0] + '</pre>');
                }
            }
            let output = $('#output');
            output.html(cmd + lines.join(''));
            // Add click event listener to each line
            const links = document.querySelectorAll('pre[data-line]');
            links.forEach(link => {
                link.addEventListener('click', () => {
                    highlightLine(link.dataset.line);
                });
            });
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

function deleteChosenFile() {
    let id = localStorage.getItem('file_id');
    if (id === null) return; // No file chosen

    localStorage.setItem('form_id', id);
    deleteFile();
    dropLocalStorage();
    $('#editor').text('');
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