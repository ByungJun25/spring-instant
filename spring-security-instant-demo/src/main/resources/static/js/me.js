const me = {
    init: function () {
        const _this = this;
        document.getElementById('me').addEventListener("click", function () {
            _this.getInfo();
        });
    },
    getInfo: function () {
        axios.get('http://localhost:8080/api/me', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            },
            withCredentials: true
        }).then(res => {
            console.log(res);
        }).catch(error => {
            console.error(error);
        })
    }
}

me.init();