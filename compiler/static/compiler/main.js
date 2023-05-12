// Load previously chosen file
let id = localStorage.getItem(FILE_ID);
if (id !== null) displayFileAndSaveId(id);
let formFileId = null;

function displayFileAndSaveId(id) {
    localStorage.setItem(FILE_ID, id);
    $.ajax({
        url: getFileShowUrl(id),
        type: GET,
        success: function (data) {
            $('#editor').text(data['code']);
        },
        error: function (data) {
            console.log(data);
        }
    });
}

function saveFileIdToForm(id, name) {
    formFileId = id;
    $('#exampleModalLabel').text('Chosen directory: ' + name);
    if (id === ROOT_ID) {
        $('#upload-tab').addClass(DISABLED);
        $('#delete-btn').addClass(DISABLED);
        $('#upload-btn').addClass(DISABLED);
    } else {
        $('#upload-tab').removeClass(DISABLED);
        $('#delete-btn').removeClass(DISABLED);
        $('#upload-btn').removeClass(DISABLED);
    }
}

function dropLocalStorage() {
    localStorage.removeItem(FILE_ID);
}

function highlightLine(line) {
    let editor = $('textarea')[0];
    let lines = editor.value.split('\n'); // Split the text into an array of lines
    let start = 0;
    let end = 0;

    // Find the starting and ending indices of the specified line
    for (let i = 0; i < lines.length; i++) {
        if (i < line - 1) {
            start += lines[i].length + 1; // Add 1 to account for the newline character
        }
        if (i === line - 1) {
            end = start + lines[i].length; // End index is start index plus line length
            break;
        }
    }

    editor.scrollTop = editor.scrollHeight * (line - 1) / lines.length;
    // Scroll to the highlighted line
    editor.setSelectionRange(start, end);
    editor.scrollIntoView({behavior: 'smooth', block: 'center'});
    editor.focus();
}

function resetForm(form) {
    form.trigger('reset');
}

function addShowHideOnAsmSections(output) {
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
}

function getErrorLine(errors, index) {
    let errorLineNumber = errors[index][1];
    if (errorLineNumber !== '-1') {
        return '<pre class="line" data-line="' + errorLineNumber + '">' + errors[index][0] + '</pre>';
    } else {
        return '<pre class="line">' + errors[index][0] + '</pre>';
    }
}

function compileFile() {
    let id = localStorage.getItem(FILE_ID);
    if (id === null) return; // No file chosen

    let form = $('#compile-form');
    $.ajax({
        url: getFileCompileUrl(id),
        type: POST,
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
            // Merge headers and bodies
            let result = []
            for (let i = 0; i < headers.length; i++) {
                result.push(headers[i] + bodies[i]);
            }
            let output = $('#output');
            output.html(cmd + result.join(''));
            // Add click event listener to each line
            addShowHideOnAsmSections(output);
            resetForm(form);
        },
        error: function (data) {
            data = data['responseJSON'];
            let cmd = "<p>" + data['cmd'] + "</p>";
            let errors = data['errors']
            let lines = []
            for (let i = 0; i < errors.length; i++) {
                lines.push(getErrorLine(errors, i));
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
            resetForm(form);
        },
    });
}

function changeSections() {
    let id = localStorage.getItem(FILE_ID);
    if (id === null) return; // No file chosen

    // Get selected text
    let textarea = $('textarea')[0];
    let start = textarea.selectionStart;
    let end = textarea.selectionEnd;
    // Calculate row numbers
    let rowStart = textarea.value.substr(0, start).split("\n").length - 1;
    let rowEnd = textarea.value.substr(0, end).split("\n").length - 1;

    // Fill form and send request
    let form = $('#sections-form');
    form.find('input[name="start"]').val(rowStart);
    form.find('input[name="end"]').val(rowEnd);
    $.ajax({
        url: getChangeSectionsUrl(id),
        type: POST,
        data: form.serialize(),
        success: function () {
            displayFileAndSaveId(id);
            resetForm(form);
        }
    });
}

function refreshTree() {
    let tree = $('#tree');
    $.ajax({
        url: getFilesTreeUrl(),
        type: GET,
        success: function (data) {
            console.log('Refreshing tree.');
            tree.html(data);
        }
    })
}


function uploadFile() {
    let form = $('#upload-form').attr('action', 'files/upload');
    // Set parent id in the form
    form.find('input[name="parent"]').val(formFileId);

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
    resetForm(form);
}

function deleteFile() {
    $.ajax({
        url: getFileDeleteUrl(formFileId),
        type: DELETE,
        async: false
    })
    refreshTree();
}

function deleteChosenFile() {
    let id = localStorage.getItem(FILE_ID);
    if (id === null) return; // No file chosen

    formFileId = id;
    deleteFile();
    dropLocalStorage();
    $('#editor').text('');
}

function createDirectory() {
    let form = $('#create-directory-form');

    // Set parent id in the form
    form.find('input[name="parent"]').val(formFileId);
    $.ajax({
        url: getCreateDirectoryUrl(),
        type: POST,
        data: form.serialize(),
        success: function () {
            console.log('Directory created.');
        }, error: function (data) {
            console.log(data);
        },
        async: false
    })
    refreshTree();
    resetForm(form);
}
