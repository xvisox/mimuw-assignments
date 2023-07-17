const FILE_ID = 'file_id';
const FILES_API = 'files/'

// Http methods
const GET = 'GET';
const POST = 'POST';
const DELETE = 'DELETE';
// Other constants
const ROOT_ID = '-1';
const DISABLED = 'disabled';

function getFileShowUrl(id) {
    return FILES_API + id + '/show';
}

function getFileCompileUrl(id) {
    return FILES_API + id + '/compile';
}

function getChangeSectionsUrl(id) {
    return FILES_API + id + '/sections';
}

function getFileDeleteUrl(id) {
    return FILES_API + id + '/delete';
}

function getCreateDirectoryUrl() {
    return FILES_API + 'directory/create';
}

function getFilesTreeUrl() {
    return FILES_API + 'tree';
}

