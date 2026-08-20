const API_BASE_URL = "http://localhost:8000/api";


async function request(endpoint) {

  const response = await fetch(
    `${API_BASE_URL}${endpoint}`
  );

  if (!response.ok) {

    throw new Error(
      `API request failed: ${response.status}`
    );

  }

  return response.json();
}


async function postRequest(
  endpoint,
  data
) {

  const response = await fetch(
    `${API_BASE_URL}${endpoint}`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify(data),
    }
  );


  if (!response.ok) {

    throw new Error(
      `API request failed: ${response.status}`
    );

  }

  return response.json();
}




export async function getHealth() {

  return request(
    "/health"
  );

}




export async function getDashboard() {

  return request(
    "/dashboard"
  );

}




export async function getFindings() {

  return request(
    "/findings"
  );

}




export async function getAcceptedRisks() {

  return request(
    "/accepted-risks"
  );

}




export async function getTickets() {

  return request(
    "/tickets"
  );

}




export async function getRiskExplanation(
  finding
) {

  return postRequest(
    "/risk-explanation",
    finding
  );

}