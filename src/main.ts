import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { NgModule, Component, ViewChild, ElementRef, AfterViewInit, OnInit } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule, Routes, Router, NavigationEnd } from '@angular/router';
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
import { faEnvelope, faLock, faArrowRight, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';
import { faGithub } from '@fortawesome/free-brands-svg-icons';
import { Title } from '@angular/platform-browser';
import { enableProdMode } from '@angular/core'; // Moved enableProdMode import here

// AuthComponent
@Component({
  selector: 'app-auth',
  template: `
    <div class="relative min-h-screen flex items-center justify-center p-4">
      <div class="relative flex flex-col md:flex-row items-center justify-center gap-12 w-full max-w-6xl z-10">
        <div class="glassmorphism p-8 rounded-2xl w-full max-w-md">
          <div [@routeAnimation]="isSignupRoute ? 'signup' : 'login'">
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
            </div>
            <div *ngIf="!isSignupRoute">
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
      transition('signup => login', [
        style({ opacity: 1, transform: 'translateX(0)' }),
        animate('300ms ease-in-out', style({ opacity: 0, transform: 'translateX(-20%)' }))
      ]),
      transition('login => signup', [
        style({ opacity: 1, transform: 'translateX(0)' }),
        animate('300ms ease-in-out', style({ opacity: 0, transform: 'translateX(20%)' }))
      ]),
      transition('signup => login, login => signup', [
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
  isSignupRoute: boolean = true;
  errorMessage: string = '';

  constructor(private router: Router, private http: HttpClient, private titleService: Title) {
    this.router.events.subscribe(() => {
      const currentUrl = this.router.url.split('?')[0];
      this.isSignupRoute = currentUrl === '/signup' || currentUrl === '/';
      if (this.isSignupRoute) {
        this.titleService.setTitle('CodeCraft - Signup');
      } else if (currentUrl === '/login') {
        this.titleService.setTitle('CodeCraft - Login');
      }
      this.email = '';
      this.password = '';
      this.errorMessage = '';
    });
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
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8); // Fixed typo: removed "Taxes"
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

  private signup(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/signup`, { email, password });
  }

  private login(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, { email, password });
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
      this.router.navigate(['/code']);
    } else {
      this.errorMessage = error || 'Authentication failed. Please try again.';
      console.log('Authentication failed:', this.errorMessage);
      this.router.navigate(['/login']);
    }
  }

  onSignupSubmit() {
    this.signup(this.email, this.password).subscribe({
      next: (response) => {
        localStorage.setItem('token', response.token);
        const decoded: any = jwtDecode(response.token);
        const username = decoded.username || this.email.split('@')[0];
        localStorage.setItem('username', username);
        this.errorMessage = '';
        this.email = '';
        this.password = '';
        this.router.navigate(['/code']);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Signup failed';
      }
    });
  }

  onLoginSubmit() {
    this.login(this.email, this.password).subscribe({
      next: (response) => {
        localStorage.setItem('token', response.token);
        const decoded: any = jwtDecode(response.token);
        const username = decoded.username || this.email.split('@')[0];
        localStorage.setItem('username', username);
        this.errorMessage = '';
        this.email = '';
        this.password = '';
        this.router.navigate(['/code']);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Login failed';
      }
    });
  }
}

// CodeComponent
@Component({
  selector: 'app-code',
  template: `
    <div class="flex flex-col items-center justify-center w-full max-w-6xl p-4">
      <div class="flex items-center justify-between w-full mb-4">
        <div class="text-4xl font-bold">
          <span class="gradient-text">CodeCraft</span>
        </div>
        <div class="flex items-center gap-4">
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
        <div #editorContainer class="w-1/2 h-[600px] border border-gray-500"></div>
        <div class="w-1/2 h-[600px] flex flex-col">
          <button 
            (click)="runCode()" 
            class="glassmorphism-button mb-4 py-2 px-4 self-start"
            [disabled]="isRunning"
          >
            <span class="text-black">{{ isRunning ? 'Running...' : 'Run Code' }}</span>
            <fa-icon [icon]="['fas', 'arrow-right']" class="text-lg glassmorphism-icon"></fa-icon>
          </button>
          <div class="mb-4">
            <textarea 
              [(ngModel)]="userInput" 
              placeholder="Enter input for your program (e.g., 'Hello' or numbers)..." 
              class="glassmorphism-input w-full h-[100px] p-4 resize-none"
              name="userInput"
            ></textarea>
          </div>
          <div class="glassmorphism p-4 rounded-xl h-full overflow-auto">
            <h3 class="text-xl font-bold text-white mb-2">Output</h3>
            <pre class="text-white whitespace-pre-wrap">{{ output }}</pre>
            <div *ngIf="error" class="text-red-500 mt-2">{{ error }}</div>
          </div>
        </div>
      </div>
    </div>
  `
})
class CodeComponent implements OnInit, AfterViewInit {
  @ViewChild('editorContainer', { static: false }) editorContainer!: ElementRef<HTMLDivElement>;
  username: string = '';
  code: string = '#include <iostream>\n#include <string>\n\nint main() {\n    std::string input;\n    std::getline(std::cin, input);\n    std::cout << "Echo: " << input << "\\n";\n    return 0;\n}'; // Updated for input
  private editor: any;
  output: string = '';
  error: string = '';
  isRunning: boolean = false;
  userInput: string = ''; // Added for user input
  private apiUrl = 'http://localhost:5000/api';

  constructor(
    private router: Router, 
    private titleService: Title,
    private http: HttpClient
  ) {
    this.titleService.setTitle('CodeCraft - Code Editor');
  }

  ngOnInit() {
    const token = localStorage.getItem('token');
    this.username = localStorage.getItem('username') || '';
    if (!token) {
      console.log('No token found, redirecting to login...');
      this.router.navigate(['/login']);
    }
  }

  ngAfterViewInit() {
    this.loadMonacoEditor();
  }

  runCode() {
    this.isRunning = true;
    this.output = '';
    this.error = '';

    const codeToRun = this.editor.getValue();
    const token = localStorage.getItem('token');

    console.log('Code:', codeToRun);
    console.log('Input:', this.userInput);
    console.log('Token:', token);

    if (!token) {
      this.error = 'Authentication token not found. Please log in again.';
      this.isRunning = false;
      console.log('No token found, redirecting to login...');
      this.router.navigate(['/login']);
      return;
    }

    this.http.post(`${this.apiUrl}/run`, 
      { code: codeToRun, language: 'cpp', input: this.userInput },
      { headers: { 'x-auth-token': token } }
    ).pipe(
      catchError(error => {
        console.error('HTTP Error:', error);
        if (error.status === 401) {
          this.error = 'Unauthorized: Invalid or expired token. Please log in again.';
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = error.error?.error || error.message || 'Error running code';
        }
        this.isRunning = false;
        return throwError(error);
      })
    ).subscribe({
      next: (response: any) => {
        console.log('Backend response:', response);
        this.output = response.output || '';
        this.error = response.error || '';
        this.isRunning = false;
      },
      error: () => {
        this.isRunning = false;
      }
    });
  }

  private loadMonacoEditor() {
    const loaderScript = document.createElement('script');
    loaderScript.src = '/assets/monaco-editor/min/vs/loader.js';
    loaderScript.async = true;
    loaderScript.onload = () => {
      console.log('Monaco loader.js loaded successfully');
      this.initializeMonacoEditor();
    };
    loaderScript.onerror = (err) => {
      console.error('Failed to load Monaco loader.js:', err);
    };
    document.body.appendChild(loaderScript);
  }

  private initializeMonacoEditor() {
    const require = (<any>window).require;
    require.config({ paths: { 'vs': '/assets/monaco-editor/min/vs' } });

    require(['vs/editor/editor.main'], () => {
      this.editor = (<any>window).monaco.editor.create(this.editorContainer.nativeElement, {
        value: this.code,
        language: 'cpp',
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: { enabled: false },
        fontSize: 23,
        readOnly: false,
        suggestOnTriggerCharacters: true,
        acceptSuggestionOnEnter: 'on',
        quickSuggestions: { other: true, comments: true, strings: true },
        parameterHints: { enabled: true },
        hover: { enabled: true }
      });

      (<any>window).monaco.languages.register({ id: 'cpp' });

      (<any>window).monaco.languages.setMonarchTokensProvider('cpp', {
        defaultToken: '',
        tokenPostfix: '.cpp',
        keywords: [
          'int', 'float', 'double', 'char', 'void', 'bool', 'class', 'struct', 'namespace',
          'if', 'else', 'while', 'for', 'switch', 'case', 'break', 'continue', 'return',
          'public', 'private', 'protected', 'virtual', 'static', 'const', 'new', 'delete',
          'using', 'try', 'catch', 'throw', 'template', 'typename'
        ],
        operators: [
          '=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=', '&&', '||', '++', '--',
          '+', '-', '*', '/', '&', '|', '^', '%', '<<', '>>', '>>>', '+=', '-=', '*=', '/=',
          '&=', '|=', '^=', '%=', '<<=', '>>=', '>>>='
        ],
        symbols: /[=><!~?:&|+\-*\/\^%]+/,
        escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
        tokenizer: {
          root: [
            [/[a-zA-Z_]\w*/, { cases: { '@keywords': 'keyword', '@default': 'identifier' } }],
            [/\/\/.*$/, 'comment'],
            [/\/\*/, 'comment', '@comment'],
            [/"([^"\\]|\\.)*$/, 'string.invalid'],
            [/"/, 'string', '@string'],
            [/#\s*include\s+<[^>]+>/, 'preprocessor'],
            [/#\s*\w+/, 'preprocessor'],
            [/[0-9]+/, 'number'],
            [/@symbols/, { cases: { '@operators': 'operator', '@default': '' } }],
            [/[\{\[\(]/, 'delimiter'],
            [/[\}\]\)]/, 'delimiter']
          ],
          comment: [
            [/[^\/*]+/, 'comment'],
            [/\*\//, 'comment', '@pop'],
            [/[\/*]/, 'comment']
          ],
          string: [
            [/[^\\"]+/, 'string'],
            [/@escapes/, 'string.escape'],
            [/\\./, 'string.escape.invalid'],
            [/"/, 'string', '@pop']
          ]
        }
      });

      (<any>window).monaco.languages.registerCompletionItemProvider('cpp', {
        triggerCharacters: ['.', '::', '->'],
        provideCompletionItems: (model: any, position: any) => {
          const textUntilPosition = model.getValueInRange({
            startLineNumber: 1,
            startColumn: 1,
            endLineNumber: position.lineNumber,
            endColumn: position.column
          });
          const word = model.getWordUntilPosition(position);
          const range = {
            startLineNumber: position.lineNumber,
            endLineNumber: position.lineNumber,
            startColumn: word.startColumn,
            endColumn: word.endColumn
          };

          const suggestions = [
            { label: 'int', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'int', documentation: 'Integer type', range },
            { label: 'float', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'float', documentation: 'Floating-point type', range },
            { label: 'double', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'double', documentation: 'Double-precision floating-point type', range },
            { label: 'char', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'char', documentation: 'Character type', range },
            { label: 'void', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'void', documentation: 'Void type', range },
            { label: 'bool', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'bool', documentation: 'Boolean type', range },
            { label: 'if', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'if (${1:condition}) {\n\t$0\n}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'If statement', range },
            { label: 'for', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'for (int ${1:i} = 0; ${1:i} < ${2:10}; ${1:i}++) {\n\t$0\n}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'For loop', range },
            { label: 'while', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'while (${1:condition}) {\n\t$0\n}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'While loop', range },
            { label: 'class', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'class ${1:ClassName} {\npublic:\n\t${1:ClassName}() {}\nprivate:\n\t$0\n};', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Class definition', range },
            { label: 'struct', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'struct ${1:StructName} {\n\t$0\n};', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Struct definition', range },
            { label: 'namespace', kind: (<any>window).monaco.languages.CompletionItemKind.Keyword, insertText: 'namespace ${1:NamespaceName} {\n\t$0\n}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Namespace definition', range },
            { label: 'cout', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'std::cout', documentation: 'Standard output stream', range },
            { label: 'cin', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'std::cin', documentation: 'Standard input stream', range },
            { label: 'endl', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'std::endl', documentation: 'End of line manipulator W', range },
            { label: 'cerr', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'std::cerr', documentation: 'Standard error stream', range },
            { label: 'clog', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'std::clog', documentation: 'Standard log stream', range },
            { label: 'printf', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'printf("${1:format}", ${2:args})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Formatted output function (stdio.h)', range },
            { label: 'scanf', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'scanf("${1:format}", ${2:args})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Formatted input function (stdio.h)', range },
            { label: 'getchar', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'getchar()', documentation: 'Read a character (stdio.h)', range },
            { label: 'putchar', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'putchar(${1:char})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Write a character (stdio.h)', range },
            { label: 'strlen', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'strlen(${1:str})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Get string length (string.h)', range },
            { label: 'strcpy', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'strcpy(${1:dest}, ${2:src})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Copy string (string.h)', range },
            { label: 'strcmp', kind: (<any>window).monaco.languages.CompletionItemKind.Function, insertText: 'strcmp(${1:str1}, ${2:str2})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Compare strings (string.h)', range },
            { label: 'vector', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'std::vector<${1:int}> ${2:v}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Dynamic array (vector)', range },
            { label: 'string', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'std::string ${1:s}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'String class (string)', range },
            { label: 'map', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'std::map<${1:int}, ${2:int}> ${3:m}', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Associative container (map)', range },
            { label: 'push_back', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'push_back(${1:value})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Add element to vector end', range },
            { label: 'size', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'size()', documentation: 'Get container size', range },
            { label: 'begin', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'begin()', documentation: 'Iterator to container beginning', range },
            { label: 'end', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'end()', documentation: 'Iterator to container end', range }
          ];

          if (textUntilPosition.match(/std::cout\s*$/)) {
            suggestions.push(
              { label: '<<', kind: (<any>window).monaco.languages.CompletionItemKind.Operator, insertText: '<< ', documentation: 'Output operator for std::cout', range },
              { label: 'flush', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'flush()', documentation: 'Flush the output buffer', range },
              { label: 'precision', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'precision(${1:n})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Set floating-point precision', range }
            );
          } else if (textUntilPosition.match(/std::cin\s*$/)) {
            suggestions.push(
              { label: '>>', kind: (<any>window).monaco.languages.CompletionItemKind.Operator, insertText: '>> ', documentation: 'Input operator for std::cin', range },
              { label: 'ignore', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'ignore(${1:n}, ${2:delim})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Ignore characters from input', range },
              { label: 'get', kind: (<any>window).monaco.languages.CompletionItemKind.Method, insertText: 'get(${1:char})', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Get a character from input', range }
            );
          } else if (textUntilPosition.match(/std::\w*\s*$/)) {
            suggestions.push(
              { label: 'cout', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'cout', documentation: 'Standard output stream', range },
              { label: 'cin', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'cin', documentation: 'Standard input stream', range },
              { label: 'endl', kind: (<any>window).monaco.languages.CompletionItemKind.Variable, insertText: 'endl', documentation: 'End of line manipulator', range },
              { label: 'vector', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'vector<${1:int}>', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Dynamic array (vector)', range },
              { label: 'string', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'string', documentation: 'String class (string)', range },
              { label: 'map', kind: (<any>window).monaco.languages.CompletionItemKind.Class, insertText: 'map<${1:int}, ${2:int}>', insertTextRules: (<any>window).monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Associative container (map)', range }
            );
          }

          return { suggestions };
        }
      });

      this.editor.onDidChangeModelContent(() => {
        this.code = this.editor.getValue();
      });

      this.editor.focus();
      console.log('Monaco Editor initialized:', this.editor);
    });
  }

  signOut() {
    console.log('Sign out initiated...');
    if (confirm('Are you sure you want to sign out?')) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      this.username = '';
      this.router.navigate(['/login']);
    }
  }
}

// LandingComponent
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
          <a 
            [routerLink]="['/signup']" 
            class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3 px-6 text-lg"
          >
            <span class="text-black">Start Coding Now</span>
          </a>
          <a 
            href="#languages" 
            (click)="scrollToLanguages($event)" 
            class="glassmorphism-button flex-1 flex items-center justify-center gap-2 py-3 px-6 text-lg"
          >
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
        <button 
          (click)="scrollToTop()" 
          class="glassmorphism-button flex items-center justify-center gap-2 py-3 px-6 text-lg mx-auto"
        >
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
            <span class="gradient-text">CodeCraft</span>
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

  constructor(public router: Router) {
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
    FontAwesomeModule
  ],
  bootstrap: [AppComponent],
  providers: [Title]
})
class AppModule {
  constructor(library: FaIconLibrary) {
    library.addIcons(faGithub, faEnvelope, faLock, faArrowRight, faSignOutAlt);
  }
}

// Google Fonts
const fontLink = document.createElement('link');
fontLink.href = 'https://fonts.googleapis.com/css2?family=Rubik:wght@400;500;700&display=swap';
fontLink.rel = 'stylesheet';
document.head.appendChild(fontLink);

// Tailwind Styles
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
  }
  html {
    scroll-behavior: smooth;
  }
  h2, input {
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
// Removed process.env check; assuming development mode for simplicity
// For production, use environment.ts and Angular CLI build configurations
function bootstrapApp(): void {
  platformBrowserDynamic()
    .bootstrapModule(AppModule)
    .then(moduleRef => {
      const injector = moduleRef.injector;
      const router = injector.get(Router);

      const token = localStorage.getItem('token');
      const currentPath = window.location.pathname;
      if (token && (currentPath === '/login' || currentPath === '/signup')) {
        console.log('User is logged in, redirecting from', currentPath, 'to /code');
        router.navigate(['/code']);
      }

      router.events.subscribe(event => {
        if (event instanceof NavigationEnd) {
          const updatedToken = localStorage.getItem('token');
          if (updatedToken && (event.url === '/login' || event.url === '/signup')) {
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