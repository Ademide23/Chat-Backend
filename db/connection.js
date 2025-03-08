const mongoose = require('mongoose');

const url = "mongodb+srv://Hon_wise:AWUlg2Wp1pt5trM5@cluster0.fttmu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

mongoose.connect(url, {
    useNewUrlParser: true, 
    useUnifiedTopology: true
}).then(() => console.log('Connected to DB')).catch((e)=> console.log('Error', e))