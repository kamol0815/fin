/**
 * Test script to simulate UzCard error -108 scenario
 * This script will help us test the improved error handling
 */
const axios = require('axios');

const BASE_URL = 'http://localhost:8989/api/uzcard-api';

async function testAddCardError108() {
    try {
        console.log('Testing UzCard add-card endpoint with error -108 scenario...');

        // Test data that might trigger error -108 (card already exists)
        const testCardData = {
            cardNumber: '8600000000000001', // Common test card number
            expireDate: '12/25',
            userPhone: '998901234567',
            userId: '672279bbacf4ade58b1c5ff3', // Replace with a valid user ID
            planId: '672279bbacf4ade58b1c5ff4', // Replace with a valid plan ID
        };

        console.log('Sending request with test data:', testCardData);

        const response = await axios.post(`${BASE_URL}/add-card`, testCardData, {
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: 30000, // 30 second timeout
        });

        console.log('Response status:', response.status);
        console.log('Response data:', JSON.stringify(response.data, null, 2));

    } catch (error) {
        console.log('Request failed as expected. Error details:');
        console.log('Status:', error.response?.status);
        console.log('Status text:', error.response?.statusText);
        console.log('Error data:', JSON.stringify(error.response?.data, null, 2));

        if (error.response?.data?.errorCode === '-108') {
            console.log('\n✅ Successfully caught error -108! Testing our improved error handling...');

            // The actual improved error handling will be triggered when this error occurs
            // Check the server logs to see if our new cleanup methods are working
        }
    }
}

async function testServerHealth() {
    try {
        const response = await axios.get('http://localhost:8989');
        console.log('✅ Server is running and responding');
        return true;
    } catch (error) {
        console.log('❌ Server is not responding:', error.message);
        return false;
    }
}

async function main() {
    console.log('=== UzCard Error -108 Test Script ===\n');

    // First check if server is running
    const serverOk = await testServerHealth();
    if (!serverOk) {
        console.log('Please make sure the bot server is running first.');
        process.exit(1);
    }

    console.log('\n=== Testing add-card endpoint ===');
    await testAddCardError108();

    console.log('\n=== Test completed ===');
    console.log('Check the server logs for detailed information about the error handling process.');
}

// Run the test
main().catch(console.error);
