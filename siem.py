"""
Visual IT SIEM usage simulation using pygame.

- Generates 3 laptops (user endpoints) and a router.
- Attacks are spawned from the router at a tempo that corresponds to a randomized "attacks per day" (0-49).
- Each attack has a label (email message, dropper, phishing, virus, TCP_packet).
- When an attack is active a Reaction Box appears. Click the Reaction Box to attempt a response.
- Outcomes: -2 for breach, +1 for defended OK. Score accumulates.
- A KPI (desired outcome) is shown in yellow at top-right.
- A small measurement module shows simple stats like total attacks, defended, breaches, detection rate.

Run: pip install pygame
Then: python siem_sim.py

Notes: 

   This is a extensible educational simulation. 
   Tweak parameters in the CONFIG section.
"""

# COE measurements and calculation

# Make red teams!
# hunters can be added; what would they do here?
# Vision and visibility: add the 
# add default laptop condition 
 #PatchLevel 

# Make a Windows laptop object. 
# This stores the twin of a Windows 11 laptop
# All of these objects shall have:
# a geoPos: where in the world is the laptop geographically 
# Owner:    "None" at first, string
# Org:   Who owns the laptop, string (name of organization)
# Charge: level of charge, on laptop 0..99 (max is 99)
# PowerState: "Off" | "On"
# LastSeen: gtick  (when was the laptop seen last)


#
# quickly check a thing on a laptop 
#
# management
#   sec side of things
# no snooping?
#  what about the 
# get file 
# get a reg key value
# get a reg key: is it set?
# get whether registry has a Key by name
#  


# Think of 'lets_' functions. These configure a new
# object. they are initializers, constructors. 
# But we don't OOP (no object orientation) so the lets_
# give out a dict. 
#  
# lets are constants, by function.
#   So think of let_ 
#   as: give me a object, with properties that are calculated.
def lets_WinDefault():
    return


# Dashboard, simple (semicircles, like a BMW car etc)

# PyGame for making graphics like circles, rects.. Mouse
import pygame
import random
import math # Mathematics functions
import time # time handling, clock, walltime

gtick = 0  # globaltick, the "time"

# Gtick is just the frame-clock
#  not a human-clock
# Time is the human-time


# sip
# sleeping
#  a cup
#  brewer 
# brewer_person 
# beans into the coffee brewer


#
## ----------- CONFIG OF SIMULATION ----------
WINDOW_W, WINDOW_H = 1000, 600
FPS = 60
DAY_SECONDS = 60.0  # length of simulated "day" in seconds (affects attack spawn rate)
MIN_ATTACKS_PER_DAY = 0
MAX_ATTACKS_PER_DAY = 49
ATTACK_TYPES = ["email message", "dropper", "phishing", "virus", "TCP_packet"]
REACTION_TIME_LIMIT = 6.0  # seconds before attack reaches target if not defended
KPI_TARGET_SCORE = 25  # desired outcome shown in yellow
BASE_DETECTION = 0.6  # base probability of successfully defending when reacted
TYPE_DETECTION_MOD = {
    "email message": 0.05,
    "dropper": -0.1,
    "phishing": -0.05,
    "virus": -0.15,
    "TCP_packet": 0.0,
}
# ----------------------------------------

pygame.init()
font = pygame.font.SysFont(None, 20)
bigfont = pygame.font.SysFont(None, 32)
screen = pygame.display.set_mode((WINDOW_W, WINDOW_H))
pygame.display.set_caption("SIEM Usage Simulation")
clock = pygame.time.Clock()


# Devices in this sim:
# ===================
#
#  simple rules for firewalls 
#    1) "fast" mode: identify, and pass-through packet always
#    2) Flag mode: flag & log all anomalies, scan quickly
#    3) "Enable drop": if anomalous packets arrive => drop & log
#    4) fw has a inspection quality (p, a probability based on 
#       SW intel + RAM amount)
#

# Versionings and the setup lazy: a real problem. 
#   drift of versions, in laptops OS and PatchLevel
#      PatchLevel increases, as a fcuntion of
#        mbit_available for host, and "time"
#   automation? 
#      Did you automate? If not, lag starts to 
#      happen. So versions drift. In Practical scenario,
#      if you do not make imaging, or deploy a non-image based
#      host installer for new Windows 11 laptops, 
#      their initial OS an dsec patches are missing. You then
#      either: 
#      1. risk & boil the Windows 11 laptops in hostile water
#      2. or constraint the Windows 11's until they've gotten patch
#      3. or have the Windows 11 "baked" properly in a safe lab - spend
#         more time manually in the process. 

def GUI_currentMargin():
    # Css-inspired method for looking up margin
    # Margin is just the true amount of pixels,
    # padded between context pixel, and the 
    # edge of a container. 
    return 2


# A Dict. Python's dict is dictionary: key-value
#  Note: keys must be unique, so in this case:
#  KPI names each must be unique
KPIPositions={"COE": {"x":3, "y": 3}}


# a X,Y Map of the GUI elements: 
def guiDrawKPI(valueString, nameOfKPIString):
    # "calc" the x,y position -- just by looking up from a table
    #   each KPI has a x,y starting position, of a rectangular 
    #   area in which the KPI is to be drawn.
    # So: Lookup a x,y 
    return


#
def showMetric(value, name_str):
    guiDrawKPI(str(value), name_str)
    return

# The S-limiting curve towards a best possible,
# depends on the cyberhostility of environment.
# COE is the amount of live threats. Integer.
# 
# Input: "COE = #of threats around, live.
def cor_Calculate(RAM_gb, SW_ver,maxLat_micros):
    global COE
    # Target stream is a 128kbits/s for 1 VOIP stream
    # concurrency is the key: how much flow mbit/s
    #
    N_current_clients = 6
    SLA_Min_kbits = 128  # One voip stream
    flowAmtMbits = N_current_clients*SLA_Min_kbits
    # We must thus process at least flowAmtMbits
    # thus the one packet time budget is actually a 
    # T / CPU_count
    # pktSizeKB=8  # runts or Giants
    # 1 cpu, then we afford: 
    microbudget=flowAmtMbits # How many microseconds we afford
    NowMilliSpend=1  
    # do: max latency microseconds, that we tolerate according to SLA
    # add a SLA profile to Fortigate
    # passthrough mode is already now implemented


# Build the firewall / appliances intelligence in here.
# verdict: good
# result:  dlv = delivered
def packetStater():
    return ({verdict: "good", result: "dlv"})


# Entities positions (router in center-left, laptops right side)
router_pos = (150, WINDOW_H // 2)
laptops = []
laptop_positions = [(720, 150), (830, 300), (720, 450)]
for i, pos in enumerate(laptop_positions):
    laptops.append({
        "id": i,
        "pos": pos,
        "breached": False,
    })

# Simulation state
score = 0
total_attacks = 0
defended = 0
breaches = 0
attacks = []  # active attack objects
last_spawn_time = time.time()
attacks_per_day = random.randint(MIN_ATTACKS_PER_DAY, MAX_ATTACKS_PER_DAY)
spawn_interval = DAY_SECONDS / max(1, attacks_per_day) if attacks_per_day > 0 else float('inf')

measurement = {
    "base_detection": BASE_DETECTION,
    "attacks_per_day": attacks_per_day,
}

# Attack object structure
# {
#   id, type, spawn_time, target_laptop, pos, progress (0..1), reached:bool
# }

attack_id_counter = 0

# Reaction Box state
reaction_active = False
current_reaction_attack = None
reaction_shown_time = 0

running = True


def spawn_attack():
    global attack_id_counter, total_attacks
    attack_type = random.choice(ATTACK_TYPES)
    target = random.choice([l for l in laptops if not l['breached']]) if any(not l['breached'] for l in laptops) else random.choice(laptops)
    a = {
        'id': attack_id_counter,
        'type': attack_type,
        'spawn_time': time.time(),
        'target': target['id'],
        'pos': list(router_pos),
        'progress': 0.0,
        'reached': False,
    }
    attack_id_counter += 1
    attacks.append(a)
    total_attacks += 1


def handle_reaction_click():
    global reaction_active, current_reaction_attack, score, defended, breaches
    if not reaction_active or current_reaction_attack is None:
        return
    a = current_reaction_attack
    # compute success chance
    base = measurement['base_detection']
    mod = TYPE_DETECTION_MOD.get(a['type'], 0.0)
    # small randomness and small penalty if the target is already stressed (breached before)
    target_breached = laptops[a['target']]['breached']
    penalty = -0.1 if target_breached else 0.0
    chance = max(0.01, min(0.99, base + mod + penalty + random.uniform(-0.12, 0.12)))
    success = random.random() < chance
    if success:
        score += 1
        defended += 1
        # remove attack
        attacks[:] = [x for x in attacks if x['id'] != a['id']]
    else:
        score -= 2
        breaches += 1
        laptops[a['target']]['breached'] = True
        # remove attack
        attacks[:] = [x for x in attacks if x['id'] != a['id']]
    reaction_active = False
    current_reaction_attack = None


while running:
    dt = clock.tick(FPS) / 1000.0
    now = time.time()

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        elif event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            mx, my = pygame.mouse.get_pos()
            if reaction_active:
                # Reaction box area
                rx, ry, rw, rh = 50, WINDOW_H - 140, 400, 100
                if rx <= mx <= rx + rw and ry <= my <= ry + rh:
                    handle_reaction_click()

    # Spawn logic: means the creation of new threats
    # Spawn = birth. 
    if now - last_spawn_time >= spawn_interval:
        last_spawn_time = now
        if attacks_per_day > 0:
            spawn_attack()
        # possible dynamic update: recalc attacks_per_day occasionally
        # but we leave static for now

    # Update attacks movement & check whether the target is reached
    for a in list(attacks):
        target_pos = laptops[a['target']]['pos']
        # linear interpolation over REACTION_TIME_LIMIT seconds
        t_passed = now - a['spawn_time']
        prog = min(1.0, t_passed / REACTION_TIME_LIMIT)
        a['progress'] = prog
        a['pos'][0] = router_pos[0] + (target_pos[0] - router_pos[0]) * prog
        a['pos'][1] = router_pos[1] + (target_pos[1] - router_pos[1]) * prog
        if prog >= 1.0 and not a['reached']:
            # attack reached target => breach if not reacted already
            a['reached'] = True
            # auto-breach
            score -= 2
            breaches += 1
            laptops[a['target']]['breached'] = True
            # remove attack
            attacks[:] = [x for x in attacks if x['id'] != a['id']]
            # clear reaction if it was for this attack
            if reaction_active and current_reaction_attack and current_reaction_attack['id'] == a['id']:
                reaction_active = False
                current_reaction_attack = None

    # If there are attacks and no active reaction, show reaction for oldest attack
    if attacks and not reaction_active:
        # present the earliest spawned attack
        attacks_sorted = sorted(attacks, key=lambda x: x['spawn_time'])
        current_reaction_attack = attacks_sorted[0]
        reaction_active = True
        reaction_shown_time = now

    # Auto-timeout for reaction (if user doesn't 
    #   click but attack still moving, we keep reaction active 
    #   until reach)

    # Drawing
    screen.fill((30, 30, 30))

    # Draw router
    pygame.draw.circle(screen, (100, 180, 255), router_pos, 36)
    rtxt = bigfont.render("Router", True, (0, 0, 0))
    screen.blit(rtxt, (router_pos[0] - rtxt.get_width() // 2, router_pos[1] - 10))

    # Draw laptops
    for l in laptops:
        color = (180, 250, 180) if not l['breached'] else (200, 80, 80)
        x, y = l['pos']
        pygame.draw.rect(screen, color, (x-40, y-25, 80, 50), border_radius=6)
        lid = font.render(f"Laptop {l['id']+1}", True, (0,0,0))
        screen.blit(lid, (x - lid.get_width()//2, y - 6))
        if l['breached']:
            br = font.render("BREACHED", True, (255,255,255))
            screen.blit(br, (x - br.get_width()//2, y + 8))

    # Draw attacks
    for a in attacks:
        ax, ay = int(a['pos'][0]), int(a['pos'][1])
        pygame.draw.circle(screen, (220, 80, 80), (ax, ay), 10)
        tlabel = font.render(a['type'], True, (255,255,255))
        screen.blit(tlabel, (ax - tlabel.get_width()//2, ay - 24))

    # Draw measurement module (left top)
    mm_x, mm_y = 20, 20
    pygame.draw.rect(screen, (40,40,40), (mm_x, mm_y, 300, 110), border_radius=6)
    mm_title = bigfont.render("Measurement Module", True, (240,240,240))
    screen.blit(mm_title, (mm_x + 8, mm_y + 6))
    lines = [
        f"Attacks per day (sim): {measurement['attacks_per_day']}",
        f"Base detection: {measurement['base_detection']:.2f}",
        f"Total attacks: {total_attacks}",
        f"Defended: {defended}",
        f"Breaches: {breaches}",
    ]
    for i, ln in enumerate(lines):
        t = font.render(ln, True, (220,220,220))
        screen.blit(t, (mm_x + 8, mm_y + 40 + i*14))

    # Draw reaction box (bottom-left)
    rx, ry, rw, rh = 50, WINDOW_H - 140, 400, 100
    pygame.draw.rect(screen, (60,60,60), (rx, ry, rw, rh), border_radius=8)
    title = font.render("Reaction Box (click to respond)", True, (255,255,255))
    screen.blit(title, (rx + 10, ry + 8))
    if reaction_active and current_reaction_attack:
        a = current_reaction_attack
        atype = font.render(f"Attack type: {a['type']}", True, (255,255,255))
        target = font.render(f"Target: Laptop {a['target']+1}", True, (255,255,255))
        timeleft = max(0.0, REACTION_TIME_LIMIT - (now - a['spawn_time']))
        timet = font.render(f"Time to impact: {timeleft:.1f}s", True, (255,255,200))
        screen.blit(atype, (rx + 10, ry + 30))
        screen.blit(target, (rx + 10, ry + 48))
        screen.blit(timet, (rx + 10, ry + 66))
    else:
        idle = font.render("No active attacks", True, (180,180,180))
        screen.blit(idle, (rx + 10, ry + 36))

    # Draw Score and KPI
    score_text = bigfont.render(f"Score: {score}", True, (255,255,255))
    screen.blit(score_text, (430, 20))

    kx, ky = WINDOW_W - 220, 20
    pygame.draw.rect(screen, (200, 180, 50), (kx, ky, 200, 64), border_radius=6)
    ktitle = bigfont.render("KPI (desired)", True, (10,10,10))
    kval = bigfont.render(f"Target: {KPI_TARGET_SCORE}", True, (10,10,10))
    screen.blit(ktitle, (kx + 12, ky + 6))
    screen.blit(kval, (kx + 12, ky + 32))

    # Tiny hint
    hint = font.render("Tip: Click the Reaction Box when an attack appears. Stay quick!", True, (200,200,200))
    screen.blit(hint, (20, WINDOW_H - 20))

    pygame.display.flip()

pygame.quit()
