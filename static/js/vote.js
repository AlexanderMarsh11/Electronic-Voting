
// - Redirect Vote page when election dropdown changes.
// - Keep Results link in navbar synced with the selected election.

(function () {
  const sel = document.getElementById('electionSelect');
  const resultsLink = document.getElementById('resultsLink');
  if (!sel) return;

  function syncResultsLink() {
    if (!resultsLink) return;
    const id = sel.value;
    resultsLink.href = `/results/${encodeURIComponent(id)}`;
  }

  sel.addEventListener('change', function () {
    const id = sel.value;
    // Redirect with query param (matches your vote route usage)
    window.location.href = `/vote?election_id=${encodeURIComponent(id)}`;
  });

  syncResultsLink();
})();