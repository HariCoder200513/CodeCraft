import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { NgModule, Component, ViewChild, ElementRef, AfterViewInit, OnInit } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule, Routes, Router, NavigationEnd, ActivatedRoute } from '@angular/router';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { trigger, state, style, animate, transition } from '@angular/animations';
import { FormsModule } from '@angular/forms';
import { HttpClientModule, HttpClient } from '@angular/common/http';
import * as THREE from 'three';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { jwtDecode } from 'jwt-decode';
import { FontAwesomeModule, FaIconLibrary } from '@fortawesome/angular-fontawesome';
import { faEnvelope, faLock, faArrowRight, faSignOutAlt, faSave, faFolderOpen, faQuestionCircle,faTrashCan } from '@fortawesome/free-solid-svg-icons';
import { faGithub } from '@fortawesome/free-brands-svg-icons';
import { Title } from '@angular/platform-browser';
import { enableProdMode } from '@angular/core';
import { ToastrModule, ToastrService } from 'ngx-toastr';

// Interface for File
interface SavedFile {
  _id: string;
  filename: string;
  language: string;
  createdAt: string;
  updatedAt: string;
}

// AuthComponent
@Component({
  selector: 'app-auth',
  template: `
    <div class="relative min-h-screen flex items-center justify-center p-4">
      <div class="relative flex flex-col md:flex-row items-center justify-center gap-12 w-full max-w-6xl z-10">
        <div class="glassmorphism p-8 rounded-2xl w-full max-w-md">
          <div [@routeAnimation]="getRouteAnimationState()">
            <div *ngIf="isSignupRoute">
              <h2 class="text-3xl font-bold text-white mb-6 text-center">Create an account</h2>
              <div class="flex gap-4 mb-6">
                <button (click)="loginWithGithub()" class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3">
                  <fa-icon [icon]="['fab', 'github']" class="text-xl glassmorphism-icon"></fa-icon>
                  <span class="text-black">GitHub</span>
                </button>
              </div>
              <div class="relative my-6">
                <div class="absolute inset-0 flex items-center">
                  <div class="w-full border-t border-gray-600"></div>
                </div>
                <div class="relative flex justify-center text-sm">
                  <span class="px-2 bg-transparent text-gray-400">OR CONTINUE WITH</span>
                </div>
              </div>
              <form (ngSubmit)="onSignupSubmit()" class="space-y-4">
                <div class="relative">
                  <fa-icon [icon]="['fas', 'envelope']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="email" 
                    placeholder="m@example.com" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="email"
                    name="email"
                    required
                    autocomplete="off"
                  >
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'lock']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="password" 
                    placeholder="Password" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="password"
                    name="password"
                    required
                    autocomplete="off"
                  >
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'question-circle']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <select 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="secretQuestion"
                    name="secretQuestion"
                    required
                  >
                    <option value="" disabled selected>Select a secret question</option>
                    <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                    <option value="What is the name of your favorite teacher?">What is the name of your favorite teacher?</option>
                    <option value="What city were you born in?">What city were you born in?</option>
                  </select>
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'question-circle']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="text" 
                    placeholder="Secret Answer" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="secretAnswer"
                    name="secretAnswer"
                    required
                    autocomplete="off"
                  >
                </div>
                <button 
                  type="submit" 
                  class="glassmorphism-button w-full flex items-center justify-center gap-2 py-3"
                >
                  <span class="text-black">Create account</span>
                  <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
                </button>
              </form>
              <div class="text-center mt-4 text-red-500" *ngIf="errorMessage">{{errorMessage}}</div>
              <div class="text-center mt-4">
                <a routerLink="/login" class="text-gray-400 hover:text-white">Already have an account? Log in</a>
              </div>
              <div class="text-center mt-2">
                <a routerLink="/forgot-password" class="text-gray-400 hover:text-white">Forgot Password?</a>
              </div>
            </div>
            <div *ngIf="isLoginRoute">
              <h2 class="text-3xl font-bold text-white mb-6 text-center">Log in</h2>
              <div class="flex gap-4 mb-6">
                <button (click)="loginWithGithub()" class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3">
                  <fa-icon [icon]="['fab', 'github']" class="text-xl glassmorphism-icon"></fa-icon>
                  <span class="text-black">GitHub</span>
                </button>
              </div>
              <div class="relative my-6">
                <div class="absolute inset-0 flex items-center">
                  <div class="w-full border-t border-gray-600"></div>
                </div>
                <div class="relative flex justify-center text-sm">
                  <span class="px-2 bg-transparent text-gray-400">OR CONTINUE WITH</span>
                </div>
              </div>
              <form (ngSubmit)="onLoginSubmit()" class="space-y-4">
                <div class="relative">
                  <fa-icon [icon]="['fas', 'envelope']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="email" 
                    placeholder="m@example.com" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="email"
                    name="email"
                    required
                    autocomplete="off"
                  >
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'lock']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="password" 
                    placeholder="Password" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="password"
                    name="password"
                    required
                    autocomplete="off"
                  >
                </div>
                <button 
                  type="submit" 
                  class="glassmorphism-button w-full flex items-center justify-center gap-2 py-3"
                >
                  <span class="text-black">Log in</span>
                  <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
                </button>
              </form>
              <div class="text-center mt-4 text-red-500" *ngIf="errorMessage">{{errorMessage}}</div>
              <div class="text-center mt-4">
                <a routerLink="/signup" class="text-gray-400 hover:text-white">Don't have an account? Sign up</a>
              </div>
              <div class="text-center mt-2">
                <a routerLink="/forgot-password" class="text-gray-400 hover:text-white">Forgot Password?</a>
              </div>
            </div>
            <div *ngIf="isResetPasswordRoute">
  <h2 class="text-3xl font-bold text-white mb-6 text-center">Reset Password</h2>
  <form (ngSubmit)="onResetPasswordSubmit()" class="space-y-4">
    <div class="relative">
      <fa-icon [icon]="['fas', 'envelope']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
      <input 
        type="email" 
        placeholder="m@example.com" 
        class="glassmorphism-input w-full pl-12 pr-4 py-3"
        [(ngModel)]="email"
        name="email"
        required
        autocomplete="off"
      >
    </div>
    <div class="relative">
      <fa-icon [icon]="['fas', 'lock']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
      <input 
        type="password" 
        placeholder="New Password" 
        class="glassmorphism-input w-full pl-12 pr-4 py-3"
        [(ngModel)]="password"
        name="newPassword"
        required
        autocomplete="off"
      >
    </div>
    <button 
      type="submit" 
      class="glassmorphism-button w-full flex items-center justify-center gap-2 py-3"
    >
      <span class="text-black">Reset Password</span>
      <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
    </button>
  </form>
  <div class="text-center mt-4 text-red-500" *ngIf="errorMessage">{{errorMessage}}</div>
  <div class="text-center mt-4">
    <a routerLink="/login" class="text-gray-400 hover:text-white">Back to Login</a>
  </div>
</div>
            <div *ngIf="isForgotPasswordRoute">
              <h2 class="text-3xl font-bold text-white mb-6 text-center">Forgot Password</h2>
              <form (ngSubmit)="onForgotPasswordSubmit()" class="space-y-4">
                <div class="relative">
                  <fa-icon [icon]="['fas', 'envelope']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="email" 
                    placeholder="m@example.com" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="email"
                    name="email"
                    required
                    autocomplete="off"
                  >
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'question-circle']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <select 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="secretQuestion"
                    name="secretQuestion"
                    required
                  >
                    <option value="" disabled selected>Select a secret question</option>
                    <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                    <option value="What is the name of your favorite teacher?">What is the name of your favorite teacher?</option>
                    <option value="What city were you born in?">What city were you born in?</option>
                  </select>
                </div>
                <div class="relative">
                  <fa-icon [icon]="['fas', 'question-circle']" class="absolute left-4 top-1/2 -translate-y-1/2 text-xl glassmorphism-icon"></fa-icon>
                  <input 
                    type="text" 
                    placeholder="Secret Answer" 
                    class="glassmorphism-input w-full pl-12 pr-4 py-3"
                    [(ngModel)]="secretAnswer"
                    name="secretAnswer"
                    required
                    autocomplete="off"
                  >
                </div>
                <button 
                  type="submit" 
                  class="glassmorphism-button w-full flex items-center justify-center gap-2 py-3"
                >
                  <span class="text-black">Verify Answer</span>
                  <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
                </button>
              </form>
              <div class="text-center mt-4 text-red-500" *ngIf="errorMessage">{{errorMessage}}</div>
              <div class="text-center mt-4">
                <a routerLink="/login" class="text-gray-400 hover:text-white">Back to Login</a>
              </div>
            </div>
          </div>
        </div>
        <div class="w-full max-w-[600px] h-[600px]">
          <canvas #rendererCanvas class="w-full h-full"></canvas>
        </div>
      </div>
    </div>
  `,
  animations: [
    trigger('routeAnimation', [
      state('signup', style({ opacity: 1, transform: 'translateX(0)' })),
      state('login', style({ opacity: 1, transform: 'translateX(0)' })),
      state('reset-password', style({ opacity: 1, transform: 'translateX(0)' })),
      state('forgot-password', style({ opacity: 1, transform: 'translateX(0)' })),
      transition('signup => login, login => signup, signup => reset-password, reset-password => signup, login => reset-password, reset-password => login, signup => forgot-password, forgot-password => signup, login => forgot-password, forgot-password => login, reset-password => forgot-password, forgot-password => reset-password', [
        style({ opacity: 0, transform: 'translateX(20%)' }),
        animate('300ms ease-in-out', style({ opacity: 1, transform: 'translateX(0)' }))
      ])
    ])
  ]
})
class AuthComponent implements AfterViewInit, OnInit {
  @ViewChild('rendererCanvas', { static: false }) rendererCanvas!: ElementRef<HTMLCanvasElement>;
  private scene!: THREE.Scene;
  private camera!: THREE.PerspectiveCamera;
  private renderer!: THREE.WebGLRenderer;
  private clock = new THREE.Clock();
  private mixer!: THREE.AnimationMixer;
  private model!: THREE.Object3D;
  private raycaster = new THREE.Raycaster();
  private mouse = new THREE.Vector2();
  private isDragging = false;
  private previousMousePosition = { x: 0, y: 0 };
  private apiUrl = 'http://localhost:5000/api/auth';

  email: string = '';
  password: string = '';
  secretQuestion: string = '';
  secretAnswer: string = '';
  isSignupRoute: boolean = false;
  isLoginRoute: boolean = false;
  isResetPasswordRoute: boolean = false;
  isForgotPasswordRoute: boolean = false;
  errorMessage: string = '';

  constructor(
    private router: Router, 
    private http: HttpClient, 
    private titleService: Title,
    private toastr: ToastrService,
    private activatedRoute: ActivatedRoute
  ) {
    console.log('AuthComponent initialized, ToastrService injected');
    setTimeout(() => {
      this.toastr.info('AuthComponent loaded', 'Debug');
    }, 1000);
    this.router.events.subscribe(() => {
      const currentUrl = this.router.url.split('?')[0];
      this.isSignupRoute = currentUrl === '/signup' || currentUrl === '/';
      this.isLoginRoute = currentUrl === '/login';
      this.isResetPasswordRoute = currentUrl === '/reset-password';
      this.isForgotPasswordRoute = currentUrl === '/forgot-password';
      if (this.isSignupRoute) {
        this.titleService.setTitle('CodeCraft - Signup');
      } else if (this.isLoginRoute) {
        this.titleService.setTitle('CodeCraft - Login');
      } else if (this.isResetPasswordRoute) {
        this.titleService.setTitle('CodeCraft - Reset Password');
      } else if (this.isForgotPasswordRoute) {
        this.titleService.setTitle('CodeCraft - Forgot Password');
      }
      this.password = '';
      this.secretQuestion = '';
      this.secretAnswer = '';
      this.errorMessage = '';
    });
    // Subscribe to query params to get email
    this.activatedRoute.queryParams.subscribe(params => {
      this.email = params['email'] || this.email;
    });
  }

  getRouteAnimationState(): string {
    if (this.isSignupRoute) return 'signup';
    if (this.isLoginRoute) return 'login';
    if (this.isResetPasswordRoute) return 'reset-password';
    if (this.isForgotPasswordRoute) return 'forgot-password';
    return 'signup';
  }

  ngOnInit() {
    const currentUrl = this.router.url.split('?')[0];
    if (currentUrl.includes('/auth/callback')) {
      console.log('Detected /auth/callback route, processing token...');
      this.handleAuthCallback();
    }
  }

  ngAfterViewInit() {
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(75, 1, 0.1, 1000);
    this.camera.position.set(0, 5, 20);
    this.renderer = new THREE.WebGLRenderer({ canvas: this.rendererCanvas.nativeElement, antialias: true, alpha: true });
    this.renderer.setSize(600, 600);
    this.renderer.setPixelRatio(window.devicePixelRatio);
    this.renderer.setClearColor(0x000000, 0);

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    this.scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(0, 10, 10);
    this.scene.add(directionalLight);

    const loader = new GLTFLoader();
    loader.load(
      'assets/planet/scene.gltf',
      (gltf) => {
        this.model = gltf.scene;
        this.scene.add(this.model);
        if (gltf.animations.length > 0) {
          this.mixer = new THREE.AnimationMixer(this.model);
          gltf.animations.forEach((clip) => this.mixer.clipAction(clip).play());
        }
        const box = new THREE.Box3().setFromObject(this.model);
        const center = box.getCenter(new THREE.Vector3());
        const size = box.getSize(new THREE.Vector3());
        this.model.position.sub(center);
        this.model.position.y += 2;
        const scale = 20 / Math.max(size.x, size.y, size.z);
        this.model.scale.set(scale, scale, scale);
      },
      (progress) => console.log(`Loading: ${(progress.loaded / progress.total * 100)}%`),
      (error) => console.error('Error loading GLTF:', error)
    );

    this.renderer.domElement.addEventListener('mousedown', this.onMouseDown.bind(this));
    this.renderer.domElement.addEventListener('mousemove', this.onMouseMove.bind(this));
    this.renderer.domElement.addEventListener('mouseup', this.onMouseUp.bind(this));
    this.animate();
  }

  private onMouseDown(event: MouseEvent) {
    event.preventDefault();
    const rect = this.renderer.domElement.getBoundingClientRect();
    this.mouse.x = ((event.clientX - rect.left) / 600) * 2 - 1;
    this.mouse.y = -((event.clientY - rect.top) / 600) * 2 + 1;
    this.raycaster.setFromCamera(this.mouse, this.camera);
    const intersects = this.model ? this.raycaster.intersectObject(this.model, true) : [];
    if (intersects.length > 0) {
      this.isDragging = true;
      this.previousMousePosition = { x: event.clientX, y: event.clientY };
    }
  }

  private onMouseMove(event: MouseEvent) {
    if (this.isDragging && this.model) {
      const deltaMove = { x: event.clientX - this.previousMousePosition.x, y: event.clientY - this.previousMousePosition.y };
      this.model.rotation.y += deltaMove.x * 0.005;
      this.model.rotation.x += deltaMove.y * 0.005;
      this.model.rotation.x = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, this.model.rotation.x));
      this.previousMousePosition = { x: event.clientX, y: event.clientY };
    }
  }

  private onMouseUp(event: MouseEvent) {
    this.isDragging = false;
  }

  private animate() {
    requestAnimationFrame(() => this.animate());
    const delta = this.clock.getDelta();
    if (this.mixer) this.mixer.update(delta);
    this.renderer.render(this.scene, this.camera);
  }

  private signup(email: string, password: string, secretQuestion: string, secretAnswer: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/signup`, { email, password, secretQuestion, secretAnswer });
  }

  private login(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, { email, password });
  }

  private resetPassword(email: string, newPassword: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/reset-password`, { email, newPassword });
  }

  private forgotPassword(email: string, secretQuestion: string, secretAnswer: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/forgot-password`, { email, secretQuestion, secretAnswer });
  }

  loginWithGithub() {
    console.log('Initiating GitHub OAuth login...');
    window.location.href = `${this.apiUrl}/github`;
  }

  private handleAuthCallback() {
    console.log('Handling auth callback...');
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const error = urlParams.get('error');

    console.log('Token:', token);
    console.log('Error:', error);

    if (token) {
      localStorage.setItem('token', token);
      const decoded: any = jwtDecode(token);
      const username = decoded.username || decoded.email.split('@')[0];
      localStorage.setItem('username', username);
      console.log('Token stored, username:', username);
      this.toastr.success('GitHub login successful!', 'Success');
      this.router.navigate(['/code']);
    } else {
      this.errorMessage = error || 'GitHub authentication failed. Please try again.';
      this.toastr.error(this.errorMessage, 'Error');
      console.log('Authentication failed:', this.errorMessage);
      this.router.navigate(['/login']);
    }
  }

  onSignupSubmit() {
    console.log('Signup submitted:', this.email);
    this.signup(this.email, this.password, this.secretQuestion, this.secretAnswer).subscribe({
      next: (response) => {
        localStorage.setItem('token', response.token);
        const decoded: any = jwtDecode(response.token);
        const username = decoded.username || this.email.split('@')[0];
        localStorage.setItem('username', username);
        this.errorMessage = '';
        this.email = '';
        this.password = '';
        this.secretQuestion = '';
        this.secretAnswer = '';
        this.toastr.success('Signup successful! Welcome to CodeCraft!', 'Success');
        this.router.navigate(['/code']);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Signup failed';
        this.toastr.error(this.errorMessage, 'Error');
        console.error('Signup error:', error);
      }
    });
  }

  onLoginSubmit() {
    console.log('Login submitted:', this.email);
    this.login(this.email, this.password).subscribe({
      next: (response) => {
        localStorage.setItem('token', response.token);
        const decoded: any = jwtDecode(response.token);
        const username = decoded.username || this.email.split('@')[0];
        localStorage.setItem('username', username);
        this.errorMessage = '';
        this.email = '';
        this.password = '';
        this.toastr.success('Login successful! Ready to code!', 'Success');
        this.router.navigate(['/code']);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Login failed';
        this.toastr.error(this.errorMessage, 'Error');
        console.error('Login error:', error);
      }
    });
  }

  onResetPasswordSubmit() {
    console.log('Reset password submitted:', this.email);
    if (!this.email) {
      this.errorMessage = 'Email is required.';
      this.toastr.error(this.errorMessage, 'Error');
      return;
    }
    this.resetPassword(this.email, this.password).subscribe({
      next: (response) => {
        this.errorMessage = '';
        this.email = '';
        this.password = '';
        this.toastr.success('Password reset successful!', 'Success');
        this.router.navigate(['/login']);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Password reset failed';
        this.toastr.error(this.errorMessage, 'Error');
        console.error('Reset password error:', error);
      }
    });
  }

  onForgotPasswordSubmit() {
    console.log('Forgot password submitted:', this.email);
    this.forgotPassword(this.email, this.secretQuestion, this.secretAnswer).subscribe({
      next: (response) => {
        this.errorMessage = '';
        this.toastr.success('Secret answer verified! Proceed to reset password.', 'Success');
        // Pass email as query parameter
        this.router.navigate(['/reset-password'], { queryParams: { email: this.email } });
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Secret answer verification failed';
        this.toastr.error(this.errorMessage, 'Error');
        console.error('Forgot password error:', error);
      }
    });
  }
}

// CodeComponent (unchanged)
@Component({
  selector: 'app-code',
  template: `
    <div class="flex flex-col items-center justify-center w-full max-w-6xl p-4">
      <div class="flex items-center justify-between w-full mb-4">
        <div class="text-4xl font-bold">
         <a routerLink="/" class="gradient-text">CodeCraft</a>
          <!-- <span class="gradient-text">CodeCraft</span> -->
        </div>
        <div class="flex items-center gap-4">
          <select 
            [(ngModel)]="selectedLanguage" 
            (change)="onLanguageChange()" 
            class="glassmorphism-input py-2 px-4"
          >
            <option value="cpp">C++</option>
            <option value="javascript">JavaScript</option>
            <option value="python">Python</option>
            <option value="java">Java</option>
          </select>
          <span class="text-2xl text-white">Welcome, {{ username }}!</span>
          <button 
            (click)="signOut()" 
            class="glassmorphism-button flex items-center justify-center gap-2 py-2 px-4"
          >
            <span class="text-black">Logout</span>
            <fa-icon [icon]="['fas', 'sign-out-alt']" class="text-lg glassmorphism-icon"></fa-icon>
          </button>
        </div>
      </div>
      <div class="flex w-full gap-4">
        <div class="w-1/4 flex flex-col">
          <div class="glassmorphism p-4 rounded-xl mb-4 h-[800px] overflow-auto">
            <h3 class="text-xl font-bold text-white mb-2">Saved Files</h3>
            <div *ngIf="isLoadingFiles" class="text-white">Loading files...</div>
            <div *ngIf="!isLoadingFiles && savedFiles.length === 0" class="text-white">No saved files</div>
            <ul *ngIf="!isLoadingFiles && savedFiles.length > 0" class="space-y-2">
  <li *ngFor="let file of savedFiles" 
      class="glassmorphism p-2 rounded cursor-pointer hover:bg-white hover:bg-opacity-20"
      [class.bg-white]="selectedFileId === file._id"
      [class.bg-opacity-10]="selectedFileId === file._id">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2" (click)="loadFile(file._id)">
        <fa-icon [icon]="['fas', 'folder-open']" class="text-lg text-white"></fa-icon>
        <span>{{ file.filename }}</span>
      </div>
      <button (click)="deleteFile(file._id)" 
              class="glassmorphism-button text-red-400 hover:text-red-600 bg-red-500 bg-opacity-20 hover:bg-opacity-30 px-2 py-1 rounded text-sm transition-all" 
              title="Delete File">
        🗑️ Delete
      </button>
    </div>
    <div class="text-sm text-gray-400">
      {{ file.language | titlecase }} • {{ file.updatedAt | date:'short' }}
    </div>
  </li>
</ul>
          </div>
        </div>
        <div class="w-3/4 flex flex-col">
          <div #editorContainer class="h-[800px] border border-gray-500"></div>
          <div class="flex flex-col gap-4 mt-4">
            <div class="flex gap-4">
              <button 
                (click)="runCode()" 
                class="glassmorphism-button py-2 px-4"
                [disabled]="isRunning"
              >
                <span class="text-black">{{ isRunning ? 'Running...' : 'Run Code' }}</span>
                <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
              </button>
              <button 
                (click)="saveCode()" 
                class="glassmorphism-button py-2 px-4"
                [disabled]="isSaving || !filename"
              >
                <span class="text-black">{{ isSaving ? 'Saving...' : 'Save Code' }}</span>
                <fa-icon [icon]="['fas', 'save']" class="text-lg glassmorphism-icon"></fa-icon>
              </button>
            </div>
            <input 
              [(ngModel)]="filename" 
              placeholder="Enter filename (e.g., mycode.cpp)" 
              class="glassmorphism-input w-full py-2 px-4"
              name="filename"
              (input)="onFilenameChange()"
            >
          </div>
          <div class="mt-4">
            <textarea 
              [(ngModel)]="userInput" 
              placeholder="Enter input for your program..." 
              class="glassmorphism-input w-full h-[100px] p-4 resize-none"
              name="userInput"
            ></textarea>
          </div>
          <div class="glassmorphism p-4 rounded-xl mt-4 overflow-auto">
            <h3 class="text-xl font-bold text-white mb-2">Output</h3>
            <pre class="text-white whitespace-pre-wrap">{{ output }}</pre>
            <div *ngIf="error" class="text-red-500 mt-2">{{ error }}</div>
            <div *ngIf="saveMessage" class="text-green-500 mt-2">{{ saveMessage }}</div>
          </div>
        </div>
      </div>
    </div>
  `
})
class CodeComponent implements OnInit, AfterViewInit {
  @ViewChild('editorContainer', { static: false }) editorContainer!: ElementRef<HTMLDivElement>;
  username: string = '';
  selectedLanguage: string = 'cpp';
  code: string = this.getDefaultCode('cpp');
  private editor: any;
  output: string = '';
  error: string = '';
  saveMessage: string = '';
  isRunning: boolean = false;
  isSaving: boolean = false;
  isLoadingFiles: boolean = false;
  userInput: string = '';
  filename: string = '';
  savedFiles: SavedFile[] = [];
  selectedFileId: string | null = null;
  private apiUrl = 'http://localhost:5000/api';

  constructor(
    private router: Router, 
    private titleService: Title,
    private http: HttpClient,
    private toastr: ToastrService
  ) {
    console.log('CodeComponent initialized, ToastrService injected');
    setTimeout(() => {
      this.toastr.info('CodeComponent loaded', 'Debug');
    }, 1000);
    this.titleService.setTitle('CodeCraft - Code Editor');
  }

  ngOnInit() {
    const token = localStorage.getItem('token');
    this.username = localStorage.getItem('username') || '';
    if (!token) {
      this.toastr.error('Authentication token not found. Please log in again.', 'Error');
      this.router.navigate(['/login']);
    } else {
      this.fetchSavedFiles();
    }
  }

  ngAfterViewInit() {
    this.loadMonacoEditor();
  }

  getDefaultCode(language: string): string {
    switch (language) {
      case 'cpp':
        return `#include <iostream>
using namespace std;

int main() {
    int num;
    cout << "Enter a number: ";
    cin >> num;
    cout << "You entered: " << num << "\\n";
    return 0;
}`;
      case 'javascript':
        return `const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Enter a number: ', (num) => {
    console.log('You entered:', parseInt(num));
    rl.close();
});`;
      case 'python':
        return `num = int(input("Enter a number: "))
print("You entered:", num)`;
      case 'java':
        return `import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a number: ");
        int num = scanner.nextInt();
        System.out.println("You entered: " + num);
        scanner.close();
    }
}`;
      default:
        return '';
    }
  }
  deleteFile(fileId: string) {
    if (!confirm('Are you sure you want to delete this file?')) return;
  
    const token = localStorage.getItem('token');
    if (!token) {
      this.toastr.error('Authentication token not found. Please log in again.', 'Error');
      this.router.navigate(['/login']);
      return;
    }
  
    this.http.delete(`${this.apiUrl}/files/delete/${fileId}`, {
      headers: { 'x-auth-token': token }
    }).pipe(
      catchError(error => {
        console.error('Delete file error:', error); // Debug backend error
        if (error.status === 401) {
          this.toastr.error('Unauthorized: Invalid or expired token. Please log in again.', 'Error');
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.toastr.error(error.error?.message || 'Failed to delete file. Please try again.', 'Error');
          // Re-fetch files to restore UI state
          this.fetchSavedFiles();
        }
        return throwError(() => error);
      })
    ).subscribe({
      next: () => {
        console.log(`File ${fileId} deleted successfully from backend`); // Debug success
        // Update savedFiles
        this.savedFiles = this.savedFiles.filter(file => file._id !== fileId);
  
        // Reset editor and state if the deleted file is selected
        if (this.selectedFileId === fileId) {
          console.log('Resetting editor for deleted file:', fileId); // Debug
          this.selectedFileId = null;
          this.filename = '';
          this.code = this.getDefaultCode(this.selectedLanguage) || '// Start coding here...';
          if (this.editor) {
            try {
              this.editor.setValue(this.code);
              this.editor.updateOptions({ readOnly: false }); // Ensure editor is editable
              this.editor.focus(); // Force UI refresh
              console.log('Editor content set to:', this.code); // Debug
            } catch (err) {
              console.error('Error updating Monaco Editor:', err);
              this.toastr.error('Failed to reset editor content.', 'Error');
            }
          } else {
            console.warn('Monaco Editor instance not found'); // Debug
            this.toastr.warning('Editor instance not available. Please refresh the page.', 'Warning');
          }
        }
  
        this.toastr.success('File deleted successfully!', 'Success');
        // Re-fetch files to ensure UI syncs with backend
        this.fetchSavedFiles();
      },
      error: (err) => {
        console.error('Unexpected error during file deletion:', err); // Debug
      }
    });
  }
  onLanguageChange() {
    this.code = this.getDefaultCode(this.selectedLanguage);
    this.filename = '';
    this.saveMessage = '';
    this.error = '';
    this.selectedFileId = null;
    if (this.editor) {
      this.editor.setValue(this.code);
      (<any>window).monaco.editor.setModelLanguage(this.editor.getModel(), this.selectedLanguage);
    }
  }

  onFilenameChange() {
    this.saveMessage = '';
    this.error = '';
  }

  fetchSavedFiles() {
    this.isLoadingFiles = true;
    this.error = '';
    const token = localStorage.getItem('token');

    if (!token) {
      this.toastr.error('Authentication token not found. Please log in again.', 'Error');
      this.isLoadingFiles = false;
      this.router.navigate(['/login']);
      return;
    }

    this.http.get<SavedFile[]>(`${this.apiUrl}/files/list`, {
      headers: { 'x-auth-token': token }
    }).pipe(
      catchError(error => {
        if (error.status === 401) {
          this.error = 'Unauthorized: Invalid or expired token. Please log in again.';
          this.toastr.error(this.error, 'Error');
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = error.error?.message || 'Error retrieving files';
          this.toastr.error(this.error, 'Error');
        }
        this.isLoadingFiles = false;
        return throwError(error);
      })
    ).subscribe({
      next: (files) => {
        this.savedFiles = files;
        this.isLoadingFiles = false;
        this.toastr.success('Files retrieved successfully!', 'Success');
      },
      error: () => {
        this.isLoadingFiles = false;
      }
    });
  }

  loadFile(fileId: string) {
    this.isLoadingFiles = true;
    this.error = '';
    this.saveMessage = '';
    const token = localStorage.getItem('token');

    if (!token) {
      this.error = 'Authentication token not found. Please log in again.';
      this.toastr.error(this.error, 'Error');
      this.isLoadingFiles = false;
      this.router.navigate(['/login']);
      return;
    }

    this.http.get(`${this.apiUrl}/files/${fileId}`, {
      headers: { 'x-auth-token': token }
    }).pipe(
      catchError(error => {
        if (error.status === 401) {
          this.error = 'Unauthorized: Invalid or expired token. Please log in again.';
          this.toastr.error(this.error, 'Error');
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = error.error?.message || 'Error loading file';
          this.toastr.error(this.error, 'Error');
        }
        this.isLoadingFiles = false;
        return throwError(error);
      })
    ).subscribe({
      next: (file: any) => {
        this.selectedFileId = fileId;
        this.filename = file.filename;
        this.selectedLanguage = file.language;
        this.code = file.code;
        if (this.editor) {
          this.editor.setValue(this.code);
          (<any>window).monaco.editor.setModelLanguage(this.editor.getModel(), this.selectedLanguage);
        }
        this.isLoadingFiles = false;
        this.toastr.success(`File "${file.filename}" loaded successfully!`, 'Success');
      },
      error: () => {
        this.isLoadingFiles = false;
      }
    });
  }

  runCode() {
    console.log('Running code...');
    this.isRunning = true;
    this.output = '';
    this.error = '';
    this.saveMessage = '';

    const codeToRun = this.editor.getValue();
    const token = localStorage.getItem('token');

    if (!token) {
      this.error = 'Authentication token not found. Please log in again.';
      this.toastr.error(this.error, 'Error');
      this.isRunning = false;
      this.router.navigate(['/login']);
      return;
    }

    this.http.post(`${this.apiUrl}/run`, 
      { code: codeToRun, language: this.selectedLanguage, input: this.userInput },
      { headers: { 'x-auth-token': token } }
    ).pipe(
      catchError(error => {
        if (error.status === 401) {
          this.error = 'Unauthorized: Invalid or expired token. Please log in again.';
          this.toastr.error(this.error, 'Error');
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = error.error?.error || error.message || 'Error running code';
          this.toastr.error(this.error, 'Error');
        }
        this.isRunning = false;
        return throwError(error);
      })
    ).subscribe({
      next: (response: any) => {
        this.output = response.output || '';
        this.error = response.error || '';
        this.isRunning = false;
        if (this.error) {
          this.toastr.error('Code execution failed!', 'Error');
        } else {
          this.toastr.success('Code executed successfully!', 'Success');
        }
      },
      error: () => {
        this.isRunning = false;
      }
    });
  }

  saveCode() {
    console.log('Saving code:', this.filename);
    if (!this.filename) {
      this.error = 'Please enter a filename';
      this.toastr.error(this.error, 'Error');
      return;
    }

    this.isSaving = true;
    this.saveMessage = '';
    this.error = '';

    const codeToSave = this.editor.getValue();
    const token = localStorage.getItem('token');

    if (!token) {
      this.error = 'Authentication token not found. Please log in again.';
      this.toastr.error(this.error, 'Error');
      this.isSaving = false;
      this.router.navigate(['/login']);
      return;
    }

    this.http.post(`${this.apiUrl}/files/save`, 
      { 
        filename: this.filename, 
        language: this.selectedLanguage, 
        code: codeToSave 
      },
      { headers: { 'x-auth-token': token } }
    ).pipe(
      catchError(error => {
        if (error.status === 401) {
          this.error = 'Unauthorized: Invalid or expired token. Please log in again.';
          this.toastr.error(this.error, 'Error');
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = error.error?.message || 'Error saving code';
          this.toastr.error(this.error, 'Error');
        }
        this.isSaving = false;
        return throwError(error);
      })
    ).subscribe({
      next: (response: any) => {
        this.saveMessage = response.message || 'Code saved successfully';
        this.isSaving = false;
        this.toastr.success(`File "${this.filename}" saved successfully!`, 'Success');
        this.fetchSavedFiles();
      },
      error: () => {
        this.isSaving = false;
      }
    });
  }

  private loadMonacoEditor() {
    const loaderScript = document.createElement('script');
    loaderScript.src = '/assets/monaco-editor/min/vs/loader.js';
    loaderScript.async = true;
    loaderScript.onload = () => {
      this.initializeMonacoEditor();
    };
    document.body.appendChild(loaderScript);
  }

  private initializeMonacoEditor() {
    const require = (<any>window).require;
    require.config({ paths: { 'vs': '/assets/monaco-editor/min/vs' } });

    require(['vs/editor/editor.main'], () => {
      this.editor = (<any>window).monaco.editor.create(this.editorContainer.nativeElement, {
        value: this.code,
        language: this.selectedLanguage,
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: { enabled: false },
        fontSize: 23
      });

      const languages = [
        {
          id: 'cpp',
          keywords: ['int', 'float', 'double', 'char', 'void', 'bool', 'class', 'struct'],
          defaultCode: this.getDefaultCode('cpp')
        },
        {
          id: 'javascript',
          keywords: ['let', 'const', 'var', 'function', 'if', 'else', 'for', 'while'],
          defaultCode: this.getDefaultCode('javascript')
        },
        {
          id: 'python',
          keywords: ['def', 'if', 'elif', 'else', 'for', 'while', 'print', 'input'],
          defaultCode: this.getDefaultCode('python')
        },
        {
          id: 'java',
          keywords: ['public', 'class', 'static', 'void', 'int', 'float', 'double', 'String'],
          defaultCode: this.getDefaultCode('java')
        }
      ];

      languages.forEach(lang => {
        (<any>window).monaco.languages.register({ id: lang.id });
        (<any>window).monaco.languages.setMonarchTokensProvider(lang.id, {
          keywords: lang.keywords,
          tokenizer: {
            root: [
              [/[a-zA-Z_]\w*/, { cases: { '@keywords': 'keyword', '@default': 'identifier' } }],
              [/\/\/.*$/, 'comment'],
              [/\/\*/, 'comment', '@comment'],
              [/"([^"\\]|\\.)*$/, 'string.invalid'],
              [/"/, 'string', '@string'],
              [/[0-9]+/, 'number']
            ],
            comment: [
              [/[^\/*]+/, 'comment'],
              [/\*\//, 'comment', '@pop'],
              [/[\/*]/, 'comment']
            ],
            string: [
              [/[^\\"]+/, 'string'],
              [/\\./, 'string.escape.invalid'],
              [/"/, 'string', '@pop']
            ]
          }
        });
      });

      this.editor.onDidChangeModelContent(() => {
        this.code = this.editor.getValue();
      });
    });
  }

  signOut() {
    if (confirm('Are you sure you want to sign out?')) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      this.username = '';
      this.savedFiles = [];
      this.selectedFileId = null;
      this.toastr.info('Logged out successfully', 'Info');
      this.router.navigate(['/login']);
    }
  }
}

// LandingComponent (unchanged)
@Component({
  selector: 'app-landing',
  template: `
    <section class="hero relative flex flex-col md:flex-row items-center justify-between min-h-screen p-4 z-10" id="hero">
  <div class="flex-1 text-left max-w-xl p-4">
    <h1 class="text-5xl md:text-6xl font-bold gradient-text mb-4">Code Anywhere, Anytime with Ease</h1>
    <p class="text-xl md:text-2xl text-gray-300 mb-8">
      Unleash your creativity with our powerful, browser-based code editor—no downloads, no hassle. Write, edit, and run code in real-time.
    </p>
    <div class="flex gap-4 mb-4">
      <a [routerLink]="['/signup']" class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3 px-6 text-lg">
        <span class="text-black">Start Coding Now</span>
      </a>
      <a href="#languages" (click)="scrollToLanguages($event)" class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3 px-6 text-lg">
        <span class="text-black">Explore Languages</span>
      </a>
    </div>
    <p class="text-sm text-gray-400">Free to use • No setup required</p>
  </div>
  <div class="flex-1 w-full max-w-[800px] h-[800px]">
    <canvas #modelCanvas class="w-full h-full"></canvas>
  </div>
</section>
<section class="languages relative py-16 px-4 z-10" id="languages">
  <h2 class="text-4xl font-bold text-white text-center mb-8">Languages You’ll Love to Code In</h2>
  <p class="text-lg text-gray-300 text-center mb-12 max-w-3xl mx-auto">
    Our browser-based editor supports a wide range of programming languages, empowering you to build everything from web apps to algorithms, right in your browser.
  </p>
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">JavaScript</h3>
      <p class="text-gray-300">Build dynamic web experiences with the web’s most popular language.</p>
    </div>
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">Python</h3>
      <p class="text-gray-300">Perfect for scripting, data analysis, or learning to code.</p>
    </div>
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">HTML/CSS</h3>
      <p class="text-gray-300">Craft stunning web pages with live previews as you type.</p>
    </div>
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">Java</h3>
      <p class="text-gray-300">Write robust, object-oriented code in a sandboxed environment.</p>
    </div>
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">C++</h3>
      <p class="text-gray-300">Tackle performance-heavy projects with our optimized editor.</p>
    </div>
    <div class="glassmorphism p-6 rounded-xl">
      <h3 class="text-2xl font-bold text-white mb-2">TypeScript</h3>
      <p class="text-gray-300">Enhance JavaScript with type safety and modern tooling.</p>
    </div>
  </div>
  <div class="text-center mt-12">
    <button (click)="scrollToTop()" class="glassmorphism-button flex items-center justify-center gap-2 py-3 px-6 text-lg mx-auto">
      <span class="text-black">Back to Top</span>
    </button>
  </div>
</section>
  `
})
class LandingComponent implements AfterViewInit {
  @ViewChild('modelCanvas', { static: false }) modelCanvas!: ElementRef<HTMLCanvasElement>;
  private scene!: THREE.Scene;
  private camera!: THREE.PerspectiveCamera;
  private renderer!: THREE.WebGLRenderer;
  private clock = new THREE.Clock();
  private mixer!: THREE.AnimationMixer;
  private model!: THREE.Object3D;
  private raycaster = new THREE.Raycaster();
  private mouse = new THREE.Vector2();
  private isDragging = false;
  private previousMousePosition = { x: 0, y: 0 };

  constructor(private router: Router, private titleService: Title) {
    this.titleService.setTitle('CodeCraft - Home');
  }
  
  ngAfterViewInit() {
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(75, 1, 0.1, 1000);
    this.camera.position.set(0, 5, 15);
    this.renderer = new THREE.WebGLRenderer({ canvas: this.modelCanvas.nativeElement, antialias: true, alpha: true });
    this.renderer.setSize(800, 800);
    this.renderer.setPixelRatio(window.devicePixelRatio);
    this.renderer.setClearColor(0x000000, 0);

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    this.scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(0, 10, 10);
    this.scene.add(directionalLight);

    const loader = new GLTFLoader();
    loader.load(
      'assets/desktop_pc/scene.gltf',
      (gltf) => {
        this.model = gltf.scene;
        this.scene.add(this.model);
        if (gltf.animations.length > 0) {
          this.mixer = new THREE.AnimationMixer(this.model);
          gltf.animations.forEach((clip) => this.mixer.clipAction(clip).play());
        }
        const box = new THREE.Box3().setFromObject(this.model);
        const center = box.getCenter(new THREE.Vector3());
        const size = box.getSize(new THREE.Vector3());
        this.model.position.sub(center);
        this.model.position.y += 1;
        const scale = 17 / Math.max(size.x, size.y, size.z);
        this.model.scale.set(scale, scale, scale);
        this.model.rotation.y = Math.PI - 4.5;
      },
      (progress) => console.log(`Loading: ${(progress.loaded / progress.total * 100)}%`),
      (error) => console.error('Error loading GLTF:', error)
    );

    this.renderer.domElement.addEventListener('mousedown', this.onMouseDown.bind(this));
    this.renderer.domElement.addEventListener('mousemove', this.onMouseMove.bind(this));
    this.renderer.domElement.addEventListener('mouseup', this.onMouseUp.bind(this));
    this.animate();
  }

  private onMouseDown(event: MouseEvent) {
    event.preventDefault();
    const rect = this.renderer.domElement.getBoundingClientRect();
    this.mouse.x = ((event.clientX - rect.left) / 800) * 2 - 1;
    this.mouse.y = -((event.clientY - rect.top) / 800) * 2 + 1;
    this.raycaster.setFromCamera(this.mouse, this.camera);
    const intersects = this.model ? this.raycaster.intersectObject(this.model, true) : [];
    if (intersects.length > 0) {
      this.isDragging = true;
      this.previousMousePosition = { x: event.clientX, y: event.clientY };
    }
  }

  private onMouseMove(event: MouseEvent) {
    if (this.isDragging && this.model) {
      const deltaMove = { x: event.clientX - this.previousMousePosition.x, y: event.clientY - this.previousMousePosition.y };
      this.model.rotation.y += deltaMove.x * 0.005;
      this.model.rotation.x += deltaMove.y * 0.005;
      this.model.rotation.x = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, this.model.rotation.x));
      this.previousMousePosition = { x: event.clientX, y: event.clientY };
    }
  }

  private onMouseUp(event: MouseEvent) {
    this.isDragging = false;
  }

  private animate() {
    requestAnimationFrame(() => this.animate());
    const delta = this.clock.getDelta();
    if (this.mixer) this.mixer.update(delta);
    this.renderer.render(this.scene, this.camera);
  }

  scrollToLanguages(event: Event) {
    event.preventDefault();
    const element = document.getElementById('languages');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  }

  scrollToTop() {
    const element = document.getElementById('hero');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  }
}

// AppComponent
@Component({
  selector: 'app-root',
  template: `
    <div class="relative min-h-screen bg-gradient-to-br from-gray-900 to-black">
      <canvas *ngIf="!isLoggedIn" #backgroundCanvas class="absolute inset-0 w-full h-full z-0"></canvas>
      <nav *ngIf="router.url !== '/code'" class="relative z-10 flex items-center justify-between p-4 bg-transparent">
        <div class="flex items-center justify-between w-full">
          <div class="text-3xl font-bold">
            <a routerLink="/" class="gradient-text">CodeCraft</a>
          </div>
          <div class="flex items-center gap-6">
            <span *ngIf="isLoggedIn" class="text-xl text-white">{{ username }}</span>
            <button 
              *ngIf="isLoggedIn" 
              (click)="signOut()" 
              class="glassmorphism-button flex items-center justify-center gap-2 py-2 px-4"
            >
              <span class="text-black">Logout</span>
              <fa-icon [icon]="['fas', 'sign-out-alt']" class="text-lg glassmorphism-icon"></fa-icon>
            </button>
            <ul *ngIf="!isLoggedIn" class="flex items-center gap-6 text-white">
              <li><a routerLink="/" class="hover:text-gray-300">Home</a></li>
              <li><a routerLink="/languages" class="hover:text-gray-300">Supported Languages</a></li>
              <li><a routerLink="/signup" class="glassmorphism-button py-2 px-4">Signup</a></li>
              <li><a routerLink="/login" class="glassmorphism-button py-2 px-4">Login</a></li>
            </ul>
          </div>
        </div>
      </nav>
      <router-outlet></router-outlet>
    </div>
  `
})
class AppComponent implements AfterViewInit {
  @ViewChild('backgroundCanvas', { static: false }) backgroundCanvas!: ElementRef<HTMLCanvasElement>;
  private backgroundScene!: THREE.Scene;
  private backgroundCamera!: THREE.PerspectiveCamera;
  private backgroundRenderer: THREE.WebGLRenderer | null = null;
  private clock = new THREE.Clock();
  private stars: THREE.Points | null = null;
  isLoggedIn: boolean = false;
  username: string = '';

  constructor(
    public router: Router,
    private toastr: ToastrService
  ) {
    console.log('AppComponent initialized, ToastrService injected');
    setTimeout(() => {
      this.toastr.info('AppComponent loaded', 'Debug');
    }, 1000);
    this.checkLoginStatus();
    this.router.events.subscribe(event => {
      if (event instanceof NavigationEnd) {
        console.log('NavigationEnd event triggered, URL:', event.url);
        this.checkLoginStatus();
      }
    });
  }

  ngAfterViewInit() {
    if (!this.isLoggedIn) {
      this.initializeStars();
    }
  }

  private checkLoginStatus() {
    const token = localStorage.getItem('token');
    this.isLoggedIn = !!token;
    this.username = localStorage.getItem('username') || '';
    console.log('Checked login status, isLoggedIn:', this.isLoggedIn, 'Username:', this.username);
    if (this.isLoggedIn && this.backgroundRenderer) {
      this.stopStarsAnimation();
    } else if (!this.isLoggedIn && !this.backgroundRenderer) {
      this.initializeStars();
    }
  }

  private initializeStars() {
    if (!this.backgroundCanvas) return;

    this.backgroundScene = new THREE.Scene();
    this.backgroundCamera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    this.backgroundCamera.position.set(0, 0, 20);
    this.backgroundRenderer = new THREE.WebGLRenderer({
      canvas: this.backgroundCanvas.nativeElement,
      antialias: true,
      alpha: true
    });
    this.backgroundRenderer.setSize(window.innerWidth, window.innerHeight);
    this.backgroundRenderer.setPixelRatio(window.devicePixelRatio);
    this.backgroundRenderer.setClearColor(0x000000, 0);

    this.addStars();
    window.addEventListener('resize', () => {
      if (this.backgroundCamera && this.backgroundRenderer) {
        this.backgroundCamera.aspect = window.innerWidth / window.innerHeight;
        this.backgroundCamera.updateProjectionMatrix();
        this.backgroundRenderer.setSize(window.innerWidth, window.innerHeight);
      }
    });
    this.animate();
  }

  private addStars() {
    const starCount = 10000;
    const positions = new Float32Array(starCount * 3);
    const velocities = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 2000;
      positions[i + 1] = (Math.random() - 0.5) * 2000;
      positions[i + 2] = (Math.random() - 0.5) * 2000;
      velocities[i] = (Math.random() - 0.5) * 0.02;
      velocities[i + 1] = (Math.random() - 0.5) * 0.02;
      velocities[i + 2] = (Math.random() - 0.5) * 0.02;
    }
    const starGeometry = new THREE.BufferGeometry();
    starGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    starGeometry.setAttribute('velocity', new THREE.BufferAttribute(velocities, 3));
    const starMaterial = new THREE.PointsMaterial({ color: 0xffffff, size: 2, sizeAttenuation: true, transparent: true, opacity: 0.8 });
    this.stars = new THREE.Points(starGeometry, starMaterial);
    this.backgroundScene.add(this.stars);
  }

  private animate() {
    if (this.isLoggedIn || !this.backgroundRenderer) return;

    requestAnimationFrame(() => this.animate());
    const delta = this.clock.getDelta();
    if (this.stars) {
      const positions = (this.stars.geometry.attributes['position'] as THREE.BufferAttribute).array as Float32Array;
      const velocities = (this.stars.geometry.attributes['velocity'] as THREE.BufferAttribute).array as Float32Array;
      for (let i = 0; i < positions.length; i += 3) {
        positions[i] += velocities[i];
        positions[i + 1] += velocities[i + 1];
        positions[i + 2] += velocities[i + 2];
        if (Math.abs(positions[i]) > 1000 || Math.abs(positions[i + 1]) > 1000 || Math.abs(positions[i + 2]) > 1000) {
          positions[i] = (Math.random() - 0.5) * 2000;
          positions[i + 1] = (Math.random() - 0.5) * 2000;
          positions[i + 2] = (Math.random() - 0.5) * 2000;
        }
      }
      (this.stars.geometry.attributes['position'] as THREE.BufferAttribute).needsUpdate = true;
    }
    this.backgroundRenderer.render(this.backgroundScene, this.backgroundCamera);
  }

  private stopStarsAnimation() {
    if (this.backgroundScene) {
      while (this.backgroundScene.children.length > 0) {
        this.backgroundScene.remove(this.backgroundScene.children[0]);
      }
    }
    this.stars = null;
    this.backgroundRenderer = null;
  }

  signOut() {
    console.log('Sign out initiated...');
    if (confirm('Are you sure you want to sign out?')) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      this.isLoggedIn = false;
      this.username = '';
      this.toastr.info('Logged out successfully', 'Info');
      this.router.navigate(['/login']);
    }
  }
}

// Routes
const routes: Routes = [
  { path: '', component: LandingComponent },
  { path: 'signup', component: AuthComponent },
  { path: 'login', component: AuthComponent },
  { path: 'auth/callback', component: AuthComponent },
  { path: 'code', component: CodeComponent },
  { path: 'reset-password', component: AuthComponent },
  { path: 'forgot-password', component: AuthComponent },
  { path: '**', redirectTo: '' }
];

// AppModule
@NgModule({
  declarations: [AppComponent, AuthComponent, CodeComponent, LandingComponent],
  imports: [
    BrowserModule,
    FormsModule,
    HttpClientModule,
    RouterModule.forRoot(routes),
    BrowserAnimationsModule,
    FontAwesomeModule,
    ToastrModule.forRoot({
      timeOut: 3000,
      positionClass: 'toast-top-right',
      preventDuplicates: true,
      progressBar: true,
      closeButton: true,
      enableHtml: false
    })
  ],
  bootstrap: [AppComponent],
  providers: [Title]
})
class AppModule {
  constructor(library: FaIconLibrary) {
    library.addIcons(faGithub, faEnvelope, faLock, faArrowRight, faSignOutAlt, faSave, faFolderOpen, faQuestionCircle);
  }
}

// Google Fonts
const fontLink = document.createElement('link');
fontLink.href = 'https://fonts.googleapis.com/css2?family=Rubik:wght@400;500;700&display=swap';
fontLink.rel = 'stylesheet';
document.head.appendChild(fontLink);

// Tailwind and Toastr Styles
const tailwindStyles = `
  @tailwind base;
  @tailwind components;
  @tailwind utilities;

  @layer components {
    .glassmorphism {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(15px);
      -webkit-backdrop-filter: blur(15px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 8px 32px 0 rgba(255, 255, 255, 0.05);
      font-family: 'Rubik', sans-serif;
    }
    .glassmorphism-input {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 0.5rem;
      color: #ffffff !important;
      outline: none;
      transition: all 0.3s ease;
      font-family: 'Rubik', sans-serif;
    }
    .glassmorphism-input:focus {
      background: #ffffff !important;
      border-color: #ffffff !important;
      color: #000000 !important;
      box-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
    }
    .glassmorphism-input::placeholder {
      color: rgba(255, 255, 255, 0.6) !important;
      font-family: 'Rubik', sans-serif;
      opacity: 1;
    }
    button.glassmorphism-button, a.glassmorphism-button {
      background: #ffffff !important;
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 0.5rem;
      color: #000000 !important;
      transition: all 0.3s ease;
      font-family: 'Rubik', sans-serif;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    button.glassmorphism-button:hover, a.glassmorphism-button:hover {
      background: #e6e6e6 !important;
      transform: translateY(-2px) scale(1.05);
      box-shadow: 0 6px 20px rgba(255, 255, 255, 0.4);
      color: #000000 !important;
    }
    button.glassmorphism-button:active, a.glassmorphism-button:active {
      transform: translateY(1px);
      box-shadow: 0 2px 10px rgba(255, 255, 255, 0.2);
    }
    button.glassmorphism-button span, a.glassmorphism-button span {
      color: #000000 !important;
    }
    .glassmorphism-icon {
      color: #ffffff !important;
      text-shadow: 0 0 4px rgba(0, 0, 0, 0.3);
      font-size: 1.5rem;
      transition: transform 0.3s ease;
    }
    button.glassmorphism-button:hover .glassmorphism-icon, a.glassmorphism-button:hover .glassmorphism-icon {
      transform: scale(1.2);
    }
    .gradient-text {
      background: linear-gradient(90deg, #ff6ec4, #7873f5);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      font-family: 'Rubik', sans-serif;
    }
    .toast-success {
      background: rgba(40, 167, 69, 0.9) !important;
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff !important;
      font-family: 'Rubik', sans-serif;
      z-index: 9999 !important;
      min-width: 200px !important;
      max-width: 250px !important;
      min-height: 50px !important;
      max-height: 70px !important;
      font-size: 14px !important;
      padding: 8px 12px !important;
      line-height: 1.2 !important;
    }
    .toast-error {
      background: rgba(220, 53, 69, 0.9) !important;
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff !important;
      font-family: 'Rubik', sans-serif;
      z-index: 9999 !important;
      min-width: 200px !important;
      max-width: 250px !important;
      min-height: 50px !important;
      max-height: 70px !important;
      font-size: 14px !important;
      padding: 8px 12px !important;
      line-height: 1.2 !important;
    }
    .toast-info {
      background: rgba(0, 123, 255, 0.9) !important;
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff !important;
      font-family: 'Rubik', sans-serif;
      z-index: 9999 !important;
      min-width: 200px !important;
      max-width: 250px !important;
      min-height: 50px !important;
      max-height: 70px !important;
      font-size: 14px !important;
      padding: 8px 12px !important;
      line-height: 1.2 !important;
    }
    .toast-title {
      font-weight: bold;
      color: #ffffff !important;
      font-size: 16px !important;
    }
    .toast-message {
      color: #ffffff !important;
      font-size: 14px !important;
    }
    .toast-progress {
      background: rgba(255, 255, 255, 0.8) !important;
      height: 4px !important;
    }
    .toast-container {
      z-index: 9999 !important;
      padding: 8px !important;
    }
  }
  html {
    scroll-behavior: smooth;
  }
  h2, input, select {
    font-family: 'Rubik', sans-serif !important;
    color: #ffffff !important;
  }
  a {
    transition: color 0.3s ease;
  }
`;
const styleSheet = document.createElement('style');
styleSheet.textContent = tailwindStyles;
document.head.appendChild(styleSheet);

// Bootstrap the Application with Error Handling
function bootstrapApp(): void {
  platformBrowserDynamic()
    .bootstrapModule(AppModule)
    .then(moduleRef => {
      const injector = moduleRef.injector;
      const router = injector.get(Router);

      const token = localStorage.getItem('token');
      const currentPath = window.location.pathname;
      if (token && (currentPath === '/login' || currentPath === '/signup' || currentPath === '/reset-password' || currentPath === '/forgot-password')) {
        console.log('User is logged in, redirecting from', currentPath, 'to /code');
        router.navigate(['/code']);
      }

      router.events.subscribe(event => {
        if (event instanceof NavigationEnd) {
          const updatedToken = localStorage.getItem('token');
          if (updatedToken && (event.url === '/login' || event.url === '/signup' || event.url === '/reset-password' || event.url === '/forgot-password')) {
            console.log('User is logged in, redirecting from', event.url, 'to /code');
            router.navigate(['/code']);
          }
        }
      });
    })
    .catch((err: unknown) => {
      console.error('Bootstrap error:', err);
      handleBootstrapError(err);
    });
}

function handleBootstrapError(err: unknown): void {
  let errorMessage = 'An unexpected error occurred during application startup.';
  
  if (err instanceof Error) {
    errorMessage = `Error: ${err.message}`;
    if (err.stack) {
      console.error('Stack trace:', err.stack);
    }
  } else if (typeof err === 'string') {
    errorMessage = err;
  }

  document.body.innerHTML = `
    <div style="text-align: center; padding: 20px; color: red;">
      <h1>Application Failed to Start</h1>
      <p>${errorMessage}</p>
      <p>Please try refreshing the page or contact support.</p>
    </div>
  `;
}

// Start the application
bootstrapApp();