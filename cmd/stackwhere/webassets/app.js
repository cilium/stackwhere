(function () {
    var input = document.getElementById("search");
    var table = document.getElementById("program-table");
    if (!input || !table) {
        return;
    }

    var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr"));
    input.addEventListener("input", function () {
        var needle = input.value.trim().toLowerCase();
        rows.forEach(function (row) {
            var text = row.textContent.toLowerCase();
            row.style.display = needle === "" || text.indexOf(needle) !== -1 ? "" : "none";
        });
    });
})();

(function () {
    var graphContainer = document.querySelector(".lifetimes-scroll");
    var instructionsPane = document.getElementById("instructions-pane-scroll");
    var instructionsDump = document.getElementById("instructions-dump");
    if (!graphContainer || !instructionsPane || !instructionsDump) {
        return;
    }

    var activeLine = null;
    var dragging = false;
    var suppressClick = false;
    var startX = 0;
    var startScrollLeft = 0;

    function onMouseMove(event) {
        if (!dragging) {
            return;
        }

        var dx = event.clientX - startX;
        if (Math.abs(dx) > 2) {
            suppressClick = true;
        }

        graphContainer.scrollLeft = startScrollLeft - dx;
        event.preventDefault();
    }

    function stopDragging() {
        if (!dragging) {
            return;
        }

        dragging = false;
        graphContainer.classList.remove("lifetimes-scroll-dragging");
        window.removeEventListener("mousemove", onMouseMove);
        window.removeEventListener("mouseup", stopDragging);
    }

    graphContainer.addEventListener("mousedown", function (event) {
        if (event.button !== 0) {
            return;
        }

        dragging = true;
        suppressClick = false;
        startX = event.clientX;
        startScrollLeft = graphContainer.scrollLeft;
        graphContainer.classList.add("lifetimes-scroll-dragging");

        window.addEventListener("mousemove", onMouseMove);
        window.addEventListener("mouseup", stopDragging);
        event.preventDefault();
    });

    graphContainer.addEventListener("click", function (event) {
        if (suppressClick) {
            suppressClick = false;
            return;
        }

        var target = event.target;
        if (!(target instanceof Element)) {
            return;
        }

        var dot = target.closest(".lifetime-dot");
        if (!dot) {
            return;
        }

        var raw = dot.getAttribute("data-raw");
        if (!raw) {
            return;
        }

        var line = instructionsDump.querySelector('.instruction-line[data-raw="' + raw + '"]');
        if (!line) {
            return;
        }

        if (activeLine) {
            activeLine.classList.remove("instruction-line-active");
        }
        line.classList.add("instruction-line-active");
        activeLine = line;

        line.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    });
})();
