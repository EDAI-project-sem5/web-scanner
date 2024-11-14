async function checkFileUploadVulnerability(url) {
  // Create a form data object
  const formData = new FormData();
  const fileContent = "<?php echo 'Malicious Code'; ?>";
  const blob = new Blob([fileContent], { type: 'application/x-php' });
  formData.append('file', blob, 'malicious.php');

  try {
      // Send the POST request with the file
      const response = await fetch(url, {
          method: 'POST',
          body: formData
      });
     console.log(response)
      // Check if the file was uploaded successfully
      if (response.ok) {
          const responseText = await response.text();
          if (responseText.includes('malicious.php')) {
              console.log('The URL is vulnerable to file upload attacks.');
          } else {
              console.log('The URL is not vulnerable to file upload attacks.');
          }
      } else {
          console.log('The URL is not vulnerable to file upload attacks.');
      }
  } catch (error) {
      console.error('Error uploading file:', error);
  }
}

// Example usage
checkFileUploadVulnerability('http://testphp.vulnweb.com/index.php');