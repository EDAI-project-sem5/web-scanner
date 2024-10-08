document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById('scan-form');
  const resultsDiv = document.getElementById('results');

  form.addEventListener('submit', function(event) {
      event.preventDefault();
      const domain = document.getElementById('domain').value;

      if (domain) {
          // Clear previous results
          resultsDiv.innerHTML = '<p>Scanning...</p>';

          // Start scanning the domain
          fetch('/scan', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({ domain })
          })
          .then(response => {
              if (!response.ok) {
                  throw new Error('Network response was not ok');
              }
              return response.text();
          })
          .then(data => {
              const eventSource = new EventSource(`/scan`);
              
              eventSource.onmessage = function(event) {
                  // Append the new message to resultsDiv
                  resultsDiv.innerHTML += `<p>${event.data}</p>`;
              };

              eventSource.onerror = function(event) {
                  resultsDiv.innerHTML += `<p>Error: ${event.data}</p>`;
                  eventSource.close();
              };
          })
          .catch(error => {
              resultsDiv.innerHTML += `<p>Error: ${error.message}</p>`;
          });
      }
  });
});
