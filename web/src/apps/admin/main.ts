import { mount } from 'svelte';
import '$lib/theme.css';
import AdminApp from './AdminApp.svelte';

export default mount(AdminApp, { target: document.getElementById('app')! });
