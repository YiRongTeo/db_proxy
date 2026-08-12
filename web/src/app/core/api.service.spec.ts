import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ApiService } from './api.service';

describe('ApiService (Task 8.5: sessions + two-level kill)', () => {
  let service: ApiService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('sessions() GETs /api/sessions with credentials and returns the directory', () => {
    const directory = [
      {
        session_id: 'sess-1',
        username: 'alice',
        db_user: 'app',
        db_type: 'mysql',
        db: 'appdb',
        started_at: '2026-08-11T08:00:00Z',
        last_seen: '2026-08-11T08:05:00Z',
      },
    ];
    service.sessions().subscribe((list) => expect(list).toEqual(directory));

    const req = http.expectOne('/api/sessions');
    expect(req.request.method).toBe('GET');
    expect(req.request.withCredentials).toBe(true);
    req.flush(directory);
  });

  it('killSession posts {session_id, mode:"query"} for a query kill', () => {
    service.killSession('sess-9', 'query').subscribe((res) => expect(res).toEqual({ killed: 'queued' }));

    const req = http.expectOne('/api/kill');
    expect(req.request.method).toBe('POST');
    expect(req.request.withCredentials).toBe(true);
    expect(req.request.body).toEqual({ session_id: 'sess-9', mode: 'query' });
    req.flush({ killed: 'queued' });
  });

  it('killSession posts {session_id, mode:"connection"} for a connection kill', () => {
    service.killSession('sess-9', 'connection').subscribe();

    const req = http.expectOne('/api/kill');
    expect(req.request.body).toEqual({ session_id: 'sess-9', mode: 'connection' });
    req.flush({ killed: 'queued' });
  });
});
