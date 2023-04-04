async function populate() {

    const requestURL = './data.json';
    const request = new Request(requestURL);
  
    const response = await fetch(request);
    const data = await response.json();
    
    var body = document.getElementById("container");
    var elem = document.createElement("h5");
    elem.innerHTML = "id : " + data[0].id;
    body.appendChild(elem);

    elem = document.createElement("h5");
    elem.innerHTML = "age : " + data[0].age;
    body.appendChild(elem);

    // test of large JSON file 
    // const requestURL1 = './large-file.json';
    // const request1 = new Request(requestURL1);
    // const response1 = await fetch(request1);
    // const data1 = await response1.json();
}
  
populate();