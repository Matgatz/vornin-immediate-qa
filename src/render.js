export function render(element, request) {
    element.innerHTML = request.query.html;
}
