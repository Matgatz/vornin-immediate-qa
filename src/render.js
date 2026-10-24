export function render(element, request) {
    element.textContent = request.query.html;
}
