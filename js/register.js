const form = document.querySelector(".signup form"),
      continueBtn = form.querySelector(".button input");

form.onsubmit = (e) => {
    e.preventDefault(); // prevent form from submitting normally
};

continueBtn.onclick = () => {
    // Create a new XMLHttpRequest 
    // Starting Ajax
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "php/registration.php", true);

    xhr.onload = () => {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                let data = xhr.response;
                console.log(data); // see server response
                // You can handle success/failure messages here
            }
        }
    };

    // Collect form data
    let formData = new FormData(form);

    // Send the form data via AJAX
    xhr.send(formData);
};
