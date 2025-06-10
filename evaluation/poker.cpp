// poker_game.cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <string>

extern "C" __declspec(dllexport) void InitGame(int numPlayers);
extern "C" __declspec(dllexport) void DealHands();
extern "C" __declspec(dllexport) void PlayBettingRound();
extern "C" __declspec(dllexport) void EvaluateHands();
extern "C" __declspec(dllexport) int GetWinner();
extern "C" __declspec(dllexport) void PrintGameState();

struct Card {
    int rank; // 2–14
    int suit; // 0–3
};

struct Player {
    std::vector<Card> hand;
    int chips;
    int currentBet;
    bool folded;
};

namespace PokerGame {
    std::vector<Card> deck;
    std::vector<Player> players;
    int pot = 0;
    std::default_random_engine rng{ std::random_device{}() };

    void ShuffleDeck() {
        deck.clear();
        for (int suit = 0; suit < 4; ++suit) {
            for (int rank = 2; rank <= 14; ++rank) {
                deck.push_back({ rank, suit });
            }
        }
        std::shuffle(deck.begin(), deck.end(), rng);
    }

    void DealCard(Player& player) {
        if (!deck.empty()) {
            player.hand.push_back(deck.back());
            deck.pop_back();
        }
    }

    std::string CardToString(const Card& c) {
        const char* ranks[] = { "", "", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A" };
        const char* suits[] = { "C", "D", "H", "S" };
        return std::string(ranks[c.rank]) + suits[c.suit];
    }

    int EvaluateHandStrength(const std::vector<Card>& hand) {
        // Naive: sum of ranks (for testing)
        int score = 0;
        for (auto& c : hand) score += c.rank;
        return score;
    }
}

void InitGame(int numPlayers) {
    PokerGame::players.clear();
    PokerGame::pot = 0;
    for (int i = 0; i < numPlayers; ++i) {
        PokerGame::players.push_back({ {}, 1000, 0, false });
    }
    PokerGame::ShuffleDeck();
}

void DealHands() {
    for (auto& player : PokerGame::players) {
        player.hand.clear();
        for (int i = 0; i < 5; ++i) {
            PokerGame::DealCard(player);
        }
    }
}

void PlayBettingRound() {
    for (auto& player : PokerGame::players) {
        if (!player.folded) {
            int bet = 10;
            player.chips -= bet;
            player.currentBet = bet;
            PokerGame::pot += bet;
        }
    }
}

void EvaluateHands() {
    int bestScore = 0;
    int winnerIdx = 0;
    for (size_t i = 0; i < PokerGame::players.size(); ++i) {
        if (!PokerGame::players[i].folded) {
            int score = PokerGame::EvaluateHandStrength(PokerGame::players[i].hand);
            if (score > bestScore) {
                bestScore = score;
                winnerIdx = static_cast<int>(i);
            }
        }
    }
    PokerGame::players[winnerIdx].chips += PokerGame::pot;
    PokerGame::pot = 0;
}

int GetWinner() {
    int bestScore = 0;
    int winnerIdx = 0;
    for (size_t i = 0; i < PokerGame::players.size(); ++i) {
        if (!PokerGame::players[i].folded) {
            int score = PokerGame::EvaluateHandStrength(PokerGame::players[i].hand);
            if (score > bestScore) {
                bestScore = score;
                winnerIdx = static_cast<int>(i);
            }
        }
    }
    return winnerIdx;
}

void PrintGameState() {
    for (size_t i = 0; i < PokerGame::players.size(); ++i) {
        auto& p = PokerGame::players[i];
        std::cout << "Player " << i << (p.folded ? " (folded)" : "") << ": ";
        for (auto& c : p.hand) std::cout << PokerGame::CardToString(c) << " ";
        std::cout << " Chips: " << p.chips << "\n";
    }
    std::cout << "Pot: " << PokerGame::pot << "\n";
}
