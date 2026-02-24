document.addEventListener('alpine:init', () => {
  Alpine.data('loginApp', () => ({
    form: {
      username: '',
      password: ''
    },
    isSubmitting: false,
    error: '',
    async init() {
      try {
        const response = await fetch('/api.session');
        const data = await response.json();
        if (data?.user) {
          window.location.href = '/';
        }
      } catch {
        // Ignore session probe errors.
      }
    },
    async submit() {
      this.error = '';
      this.isSubmitting = true;
      try {
        const response = await fetch('/api.login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.form)
        });
        const data = await response.json();
        if (!response.ok) {
          this.error = data?.error ?? '登录失败';
          return;
        }
        window.location.href = '/';
      } catch (error) {
        this.error = error?.message ?? '网络错误，请重试';
      } finally {
        this.isSubmitting = false;
      }
    }
  }));
});
