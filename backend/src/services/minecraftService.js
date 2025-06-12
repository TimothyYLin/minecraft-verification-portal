const { MC_SERVICES_API_URL } = require('@/config/constants');

async function getMinecraftProfile(username) {
    try{
        const response = await fetch(`${MC_SERVICES_API_URL}/${username}`);
        if(response.status === 200){
            const data = await response.json();
            return { uuid: data.id, name: data.name };
        }
        return null;
    }catch(error){
        console.error("Error fetching from Mojang API:", error);
        return null;
    }
}

module.exports = { getMinecraftProfile };
