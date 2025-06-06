//TODO: Move this to .env
const API_BASE_URL = 'http://localhost:3000/api';

/**
 * Helper function to handle fetch responses.
 * @param {Response} response - Fetch response object
 * @returns {Promise<object>} JSON response from server
 * @throws {Error} If API call fails or returns an error status
 */
async function handleResponse(response){
    if(!response.ok){
        let errorData = null;
        try{
            errorData = await response.json();
        }catch(e){
            // Fall through catching invalid JSON
        }

        const errorMessage = (errorData && errorData.error) || (errorData && errorData.message) || `HTTP error! status: ${response.status}`;
        const error = new Error(errorMessage);

        if(errorData && errorData.code){
            error.code = errorData.code;
        }

        throw error;
    }

    if(response.status === 204){
        return {};
    }

    try {
        return await response.json();
    }catch(e){
        console.error("Failed to parse JSON from a successful respons:", e);
        throw new Error("The server's response was successful, but the data was not in the correct format.");
    }
}

/**
 * Helper function for network errors and provide better message
 */
function handleFetchError(error){
    console.error('API Fetch Error:', error);
    if(error instanceof TypeError && error.message === 'Failed to fetch'){
        throw new Error('Unable to connect to the server. Please check your network connection or try again later.');
    }
    throw error;
}


/**
 * Requests to register the user
 * @param {string} email User's email
 * @param {string} password User's password
 * @returns {Promise<object>} JSON response from server
 * @throws {Error} If API call fails or returns with error status.
 */
export async function registerUser(email, password){
    try{
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        return handleResponse(response);
    }catch(error){
        console.error('Error during registration:', error);
        handleFetchError(error);
    }
}

/**
 * Requests to resend the verification email
 * @param {string} email User's email
 * @returns {Promise<object>} The JSON response from the server
 */
export async function resendVerificationEmail(email){
    try{
        const response = await fetch(`${API_BASE_URL}/resend-verification`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });
        return handleResponse(response);
    }catch(error){
        handleFetchError(error);
    }
}