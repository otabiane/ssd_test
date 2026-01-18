const UiManager = {
    bytesToSize: function(bytes) {
        var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 Byte';
        var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
        return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
    },

    toggleSidebar: function() {
        const wrapper = document.getElementById("navbar-wrapper");
        const html = document.getElementById("html");
        
        if (wrapper.style.marginLeft === "250px") {
            wrapper.style.marginLeft = "0px";
            html.classList.remove('nav-open');
        } else {
            wrapper.style.marginLeft = "250px";
            html.classList.add('nav-open');
        }
    },

    showToast: function(icon, title) {
        const Toast = Swal.mixin({
            toast: true,
            position: 'bottom-end',
            showConfirmButton: false,
            timer: 5000,
            timerProgressBar: true,
            onOpen: (toast) => {
                toast.addEventListener('mouseenter', Swal.stopTimer);
                toast.addEventListener('mouseleave', Swal.resumeTimer);
            }
        });
        Toast.fire({ icon: icon, title: title });
    }
};