// MongoDB'dagi pending transactionlarni bekor qilish
const mongoose = require('mongoose');

const MONGODB_URI = "mongodb://localhost:27017/munajjim";

async function cancelPendingTransactions() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB');

        const Transaction = mongoose.model('Transaction', new mongoose.Schema({}, { strict: false }));

        // Barcha PENDING transactionlarni topish
        const pendingTransactions = await Transaction.find({
            status: 'PENDING',
            userId: new mongoose.Types.ObjectId('68f76fad68b35cf94cd043f8')
        });

        console.log(`Found ${pendingTransactions.length} pending transactions`);

        // Ularni CANCELED qilish
        const result = await Transaction.updateMany(
            {
                status: 'PENDING',
                userId: new mongoose.Types.ObjectId('68f76fad68b35cf94cd043f8')
            },
            {
                $set: {
                    status: 'CANCELED',
                    state: -1,
                    cancelTime: new Date(),
                    reason: 1 // Manual cancellation
                }
            }
        );

        console.log(`Updated ${result.modifiedCount} transactions to CANCELED`);

        await mongoose.disconnect();
        console.log('Done!');
        process.exit(0);
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
}

cancelPendingTransactions();
